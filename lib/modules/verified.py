# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Same-process resolution and open-inode artifact capabilities for adapters."""

from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
import dataclasses
import os
from pathlib import Path
import tempfile
from typing import BinaryIO

from lib.modules import Module
from lib.modules.archive import inspect_zip, read_allowlisted_members
from lib.modules.catalog import ModuleCatalog
from lib.modules.locks import (
    ArtifactLock,
    LockError,
    ModuleLock,
    open_verified_cached_artifact,
    load_canonical_lock,
    verify_apk_identity,
)
from lib.modules.resolver import (
    CompatibilityDecision,
    Resolution,
    load_profile,
    resolve_profile,
)


@dataclasses.dataclass(frozen=True)
class VerifiedArchiveMember:
    """Immutable lock metadata for one verified allowlisted archive member."""

    name: str
    size: int
    sha256: str
    apk_package_name: str | None
    apk_version_code: int | None
    apk_signer_sha256: str | None


@dataclasses.dataclass(frozen=True)
class VerifiedArtifact:
    """Locked metadata plus capability-based access to one verified inode."""

    id: str
    kind: str
    role: str
    version: str
    size: int
    sha256: str
    apk_package_name: str | None
    apk_version_code: int | None
    apk_signer_sha256: str | None
    archive_members: tuple[VerifiedArchiveMember, ...]
    archive_apk_signers: tuple[tuple[str, str], ...]
    license: str | None
    source_offer_required: bool
    corresponding_source_artifact: str | None
    allowed_output_scopes: tuple[str, ...]
    _source: BinaryIO = dataclasses.field(repr=False, compare=False)

    @contextmanager
    def open(self) -> Iterator[BinaryIO]:
        """Open a new reader for the already verified inode.

        No cache pathname, profile pathname, lock pathname, or URL is exposed to
        an adapter.  The reader remains tied to the verified inode even if a
        cache directory entry is replaced after verification.
        """

        # An ordinary dup would share the source's open-file-description offset,
        # making nested or concurrent readers interfere with each other.  Pin
        # the verified inode with a dup while opening a fresh read description
        # through procfs, which is already required by artifact verification.
        anchor = os.dup(self._source.fileno())
        try:
            descriptor = os.open(
                f'/proc/self/fd/{anchor}',
                os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0),
            )
        finally:
            os.close(anchor)
        with os.fdopen(descriptor, 'rb') as source:
            yield source


@dataclasses.dataclass(frozen=True)
class LockedAdapterContext:
    module_id: str
    module_version: str
    profile_id: str
    rom_family: str
    output_scope: str
    lock_sha256: str
    selection_fingerprint: str
    decision: CompatibilityDecision
    trusted_signers: tuple[tuple[str, str], ...]
    artifacts: tuple[VerifiedArtifact, ...]

    def artifact(self, artifact_id: str) -> VerifiedArtifact:
        matches = tuple(item for item in self.artifacts if item.id == artifact_id)
        if len(matches) != 1:
            raise KeyError(f'locked artifact is unavailable: {artifact_id}')
        return matches[0]


class VerifiedSelection:
    """Resolved selection whose verified artifact descriptors remain live."""

    def __init__(
        self,
        resolution: Resolution,
        contexts: tuple[LockedAdapterContext, ...],
        stack: ExitStack,
    ) -> None:
        self.resolution = resolution
        self.contexts = contexts
        self._stack = stack

    def close(self) -> None:
        self._stack.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def _verify_open_artifact(
    artifact: ArtifactLock,
    source: BinaryIO,
    *,
    verify_apks: bool,
) -> None:
    descriptor = source.fileno()
    descriptor_path = Path(f'/proc/self/fd/{descriptor}')
    if artifact.archive is not None:
        inspection = inspect_zip(
            descriptor_path,
            allowlisted_members=artifact.archive.allowlisted_members,
            limits=artifact.archive.limits(),
        )
        inspected = {member.name: member for member in inspection.members}
        apk_members = tuple(
            expected.name for expected in artifact.archive.members
            if verify_apks and expected.apk is not None
        )
        member_data = read_allowlisted_members(
            descriptor_path,
            apk_members,
            allowlisted_members=artifact.archive.allowlisted_members,
            limits=artifact.archive.limits(),
        )
        for expected in artifact.archive.members:
            actual = inspected.get(expected.name)
            if actual is None or (
                actual.size != expected.size or actual.sha256 != expected.sha256
            ):
                raise LockError(
                    f'archive member does not match its lock: {expected.name}'
                )
            if verify_apks and expected.apk is not None:
                data = member_data[expected.name]
                with tempfile.TemporaryFile() as nested_apk:
                    nested_apk.write(data)
                    nested_apk.flush()
                    nested_apk.seek(0)
                    nested_descriptor = nested_apk.fileno()
                    verify_apk_identity(
                        Path(f'/proc/self/fd/{nested_descriptor}'),
                        expected.apk,
                        pass_fds=(nested_descriptor,),
                    )
    if verify_apks and artifact.apk is not None:
        verify_apk_identity(
            descriptor_path,
            artifact.apk,
            pass_fds=(descriptor,),
        )
    source.seek(0)


def open_verified_selection(
    catalog: ModuleCatalog,
    lock_path: Path,
    profile_path: Path,
    cache_dir: Path,
    *,
    verify_apks: bool = True,
) -> VerifiedSelection:
    """Resolve canonical inputs and retain verified cache inodes until close."""

    lock, lock_sha256 = load_canonical_lock(lock_path)
    resolution = resolve_profile(
        catalog,
        load_profile(profile_path),
        lock,
        lock_sha256,
    )
    lock_by_module: Mapping[str, ModuleLock] = {
        module.id: module for module in lock.modules
    }
    decisions = {item.module: item for item in resolution.decisions}
    catalog_modules = {module.id: module for module in catalog.modules}
    stack = ExitStack()
    try:
        contexts: list[LockedAdapterContext] = []
        for module_id in resolution.selected_modules:
            locked_module = lock_by_module[module_id]
            artifacts: list[VerifiedArtifact] = []
            for artifact in locked_module.artifacts:
                if (
                    artifact.legal is not None
                    and resolution.profile.output_scope
                    not in artifact.legal.allowed_output_scopes
                ):
                    raise LockError(
                        f'artifact forbids the selected output scope: {artifact.id}'
                    )
                source = stack.enter_context(
                    open_verified_cached_artifact(artifact, cache_dir)
                )
                _verify_open_artifact(
                    artifact,
                    source,
                    verify_apks=verify_apks,
                )
                artifacts.append(VerifiedArtifact(
                    id=artifact.id,
                    kind=artifact.kind,
                    role=artifact.role,
                    version=artifact.version,
                    size=artifact.size,
                    sha256=artifact.sha256,
                    apk_package_name=(
                        artifact.apk.package_name if artifact.apk else None
                    ),
                    apk_version_code=(
                        artifact.apk.version_code if artifact.apk else None
                    ),
                    apk_signer_sha256=(
                        artifact.apk.signer_sha256 if artifact.apk else None
                    ),
                    archive_members=tuple(
                        VerifiedArchiveMember(
                            name=member.name,
                            size=member.size,
                            sha256=member.sha256,
                            apk_package_name=(
                                member.apk.package_name if member.apk else None
                            ),
                            apk_version_code=(
                                member.apk.version_code if member.apk else None
                            ),
                            apk_signer_sha256=(
                                member.apk.signer_sha256 if member.apk else None
                            ),
                        )
                        for member in artifact.archive.members
                    ) if artifact.archive else (),
                    archive_apk_signers=tuple(
                        (member.name, member.apk.signer_sha256)
                        for member in artifact.archive.members
                        if member.apk is not None
                    ) if artifact.archive else (),
                    license=artifact.legal.license if artifact.legal else None,
                    source_offer_required=(
                        artifact.legal.source_offer_required
                        if artifact.legal else False
                    ),
                    corresponding_source_artifact=(
                        artifact.source.corresponding_source_artifact
                        if artifact.source else None
                    ),
                    allowed_output_scopes=(
                        artifact.legal.allowed_output_scopes
                        if artifact.legal else ()
                    ),
                    _source=source,
                ))
            contexts.append(LockedAdapterContext(
                module_id=module_id,
                module_version=locked_module.version,
                profile_id=resolution.profile.id,
                rom_family=resolution.profile.rom_family,
                output_scope=resolution.profile.output_scope,
                lock_sha256=resolution.lock_sha256,
                selection_fingerprint=resolution.fingerprint,
                decision=decisions[module_id],
                trusted_signers=tuple(sorted(
                    (root.type, root.value)
                    for root in catalog_modules[module_id].verification.trust_roots
                )),
                artifacts=tuple(artifacts),
            ))
        return VerifiedSelection(resolution, tuple(contexts), stack)
    except BaseException:
        stack.close()
        raise


def construct_locked_adapters(
    selection: VerifiedSelection,
    factories: Mapping[str, Callable[[LockedAdapterContext], Module]],
) -> tuple[tuple[str, Module], ...]:
    """Construct every selected native adapter before OTA unpack or mutation."""

    # Validate the complete registry boundary before invoking any constructor.
    # This ensures a missing or accidentally callable-only entry cannot cause a
    # partial set of adapter constructors to run.
    contexts_by_id = {context.module_id: context for context in selection.contexts}
    if len(contexts_by_id) != len(selection.contexts):
        raise RuntimeError('Locked selection contains duplicate module IDs')
    for module_id in contexts_by_id:
        factory = factories.get(module_id)
        if factory is None:
            raise RuntimeError(
                f'No trusted locked adapter is registered: {module_id}'
            )
        if not isinstance(factory, type) or not issubclass(factory, Module):
            raise RuntimeError(
                f'Locked adapter factory is an invalid module: {module_id}'
            )

    result: list[tuple[str, Module]] = []
    for context in selection.contexts:
        factory = factories[context.module_id]
        adapter = factory(context)
        if not isinstance(adapter, Module):
            raise RuntimeError(
                f'Locked adapter factory returned an invalid module: '
                f'{context.module_id}'
            )
        result.append((context.module_id, adapter))
    return tuple(result)
