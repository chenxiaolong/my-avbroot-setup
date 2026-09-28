# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Deterministic artifact locks, content-addressed caching, and verification."""

from collections.abc import Callable, Iterable
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Annotated, BinaryIO, ClassVar, Iterator, Literal, Self
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from lib.modules.archive import (
    ArchiveLimits,
    inspect_zip,
    read_allowlisted_members,
)
from lib.modules.licenses import LICENSE_PATTERN
from lib.modules.registry import MODULE_ID_PATTERN


SHA256_PATTERN = re.compile(r'^[0-9a-f]{64}$')
ARTIFACT_ID_PATTERN = re.compile(r'^[a-z][a-z0-9._-]*$')
MAX_LOCK_FILE_BYTES = 16 * 1024 * 1024
ANDROID_PACKAGE_PATTERN = re.compile(
    r'^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$'
)
NonBlankString = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, pattern=r'.*\S.*'),
]
ArtifactRole = Literal[
    'injection-input',
    'corresponding-source',
    'verification-evidence',
]


def _url_origin(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or '').encode('idna').decode('ascii').lower()
    port = parsed.port
    if port is None or port == 443:
        return f'{parsed.scheme.lower()}://{host.lower()}'
    return f'{parsed.scheme.lower()}://{host.lower()}:{port}'


def _validate_public_https_url(value: str, *, origin_only: bool = False) -> None:
    if (
        not value.isascii()
        or '\\' in value
        or any(ord(character) <= 0x20 or ord(character) == 0x7f for character in value)
    ):
        raise ValueError('HTTPS URL must use printable ASCII without backslashes')
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname:
        raise ValueError('URL must be absolute HTTPS')
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError('HTTPS URL cannot contain credentials or fragments')
    # Accessing port also rejects malformed or out-of-range port syntax.
    parsed.port
    if origin_only and (parsed.path not in ('', '/') or parsed.query):
        raise ValueError('allowed HTTPS origin cannot contain a path or query')
    hostname = parsed.hostname.rstrip('.').lower()
    if hostname == 'localhost' or hostname.endswith('.localhost'):
        raise ValueError('HTTPS URL cannot use a local hostname')
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError('HTTPS URL cannot use a non-global IP address')


class LockError(ValueError):
    """An artifact lock or cached object failed closed."""


class LockModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra='forbid', frozen=True)


class ApkIdentity(LockModel):
    package_name: NonBlankString
    version_code: StrictInt = Field(ge=1)
    signer_sha256: str

    @field_validator('package_name')
    @classmethod
    def validate_package_name(cls, value: str) -> str:
        if not ANDROID_PACKAGE_PATTERN.fullmatch(value):
            raise ValueError('APK package name must be a canonical Android application ID')
        return value

    @field_validator('signer_sha256')
    @classmethod
    def validate_signer(cls, value: str) -> str:
        normalized = value.replace(':', '').lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError('APK signer SHA-256 must contain exactly 64 hex digits')
        return normalized


class ArchiveMember(LockModel):
    name: NonBlankString
    size: StrictInt = Field(ge=0)
    sha256: str
    apk: ApkIdentity | None = None

    @field_validator('sha256')
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not SHA256_PATTERN.fullmatch(value):
            raise ValueError('archive member sha256 must be lowercase SHA-256 hex')
        return value


class ArchivePolicy(LockModel):
    members: tuple[ArchiveMember, ...]
    max_members: StrictInt = Field(default=4096, ge=1)
    max_member_size: StrictInt = Field(default=128 * 1024 * 1024, ge=1)
    max_total_size: StrictInt = Field(default=512 * 1024 * 1024, ge=1)
    max_expansion_ratio: StrictInt = Field(default=200, ge=1)
    max_streamed_bytes: StrictInt = Field(default=512 * 1024 * 1024, ge=1)

    @field_validator('members')
    @classmethod
    def validate_members(
        cls,
        values: tuple[ArchiveMember, ...],
    ) -> tuple[ArchiveMember, ...]:
        if not values:
            raise ValueError('archive allowlist cannot be empty')
        names = [member.name for member in values]
        if len(names) != len(set(names)):
            raise ValueError('archive allowlisted members must be unique')
        if names != sorted(names):
            raise ValueError('archive allowlisted members must use canonical name order')
        return values

    @property
    def allowlisted_members(self) -> tuple[str, ...]:
        return tuple(member.name for member in self.members)

    def limits(self) -> ArchiveLimits:
        return ArchiveLimits(
            max_members=self.max_members,
            max_member_size=self.max_member_size,
            max_total_size=self.max_total_size,
            max_expansion_ratio=self.max_expansion_ratio,
            max_streamed_bytes=self.max_streamed_bytes,
        )


class SourceVerification(LockModel):
    repository_url: NonBlankString
    metadata_name: NonBlankString
    metadata_sha256: str
    signature_types: tuple[
        Literal[
            'x509-cert-sha256',
            'openpgp-primary',
            'openpgp-subkey',
            'github-attestation',
        ],
        ...,
    ]

    @field_validator('repository_url')
    @classmethod
    def validate_repository_url(cls, value: str) -> str:
        _validate_public_https_url(value)
        return value

    @field_validator('metadata_sha256')
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not SHA256_PATTERN.fullmatch(value):
            raise ValueError('metadata_sha256 must be lowercase SHA-256 hex')
        return value

    @field_validator('signature_types')
    @classmethod
    def validate_signatures(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or len(values) != len(set(values)):
            raise ValueError('source signature types must be non-empty and unique')
        return values


class ArtifactSource(LockModel):
    """Immutable upstream source identity and optional locked correspondence."""

    url: NonBlankString
    revision: NonBlankString
    corresponding_source_artifact: str | None = None

    @field_validator('url')
    @classmethod
    def validate_url(cls, value: str) -> str:
        _validate_public_https_url(value)
        return value

    @field_validator('corresponding_source_artifact')
    @classmethod
    def validate_corresponding_source(cls, value: str | None) -> str | None:
        if value is not None and not ARTIFACT_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid corresponding-source artifact ID: {value!r}')
        return value


class ArtifactLegal(LockModel):
    """Per-artifact redistribution and corresponding-source requirements."""

    license: NonBlankString
    source_offer_required: StrictBool
    allowed_output_scopes: tuple[
        Literal['local-unpublished', 'private', 'shared', 'published'],
        ...,
    ] = Field(min_length=1)

    @field_validator('license')
    @classmethod
    def validate_license(cls, value: str) -> str:
        if not LICENSE_PATTERN.fullmatch(value):
            raise ValueError('license must be an SPDX identifier or LicenseRef')
        return value

    @field_validator('allowed_output_scopes')
    @classmethod
    def validate_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError('artifact output scopes must be unique')
        return values


class ArtifactLock(LockModel):
    id: str
    kind: Literal['apk', 'zip', 'jar', 'json', 'signature', 'other']
    role: ArtifactRole = 'injection-input'
    immutable_url: NonBlankString
    allowed_origins: tuple[NonBlankString, ...]
    version: NonBlankString
    size: StrictInt = Field(ge=1)
    sha256: str
    apk: ApkIdentity | None = None
    archive: ArchivePolicy | None = None
    source_verification: SourceVerification | None = None
    source: ArtifactSource | None = None
    legal: ArtifactLegal | None = None

    @field_validator('id')
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not ARTIFACT_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid artifact ID: {value!r}')
        return value

    @field_validator('immutable_url')
    @classmethod
    def validate_url(cls, value: str) -> str:
        _validate_public_https_url(value)
        return value

    @field_validator('allowed_origins')
    @classmethod
    def validate_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError('allowed origins must be non-empty and unique')
        for value in values:
            _validate_public_https_url(value, origin_only=True)
        if len(values) != len({_url_origin(value) for value in values}):
            raise ValueError('allowed origins must be non-empty and unique')
        return values

    @field_validator('sha256')
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not SHA256_PATTERN.fullmatch(value):
            raise ValueError('sha256 must be lowercase SHA-256 hex')
        return value

    @model_validator(mode='after')
    def validate_kind_metadata(self) -> Self:
        if _url_origin(self.immutable_url) not in {
            _url_origin(origin) for origin in self.allowed_origins
        }:
            raise ValueError('artifact URL origin must be explicitly allowlisted')
        if (self.kind == 'apk') != (self.apk is not None):
            raise ValueError('APK artifacts require APK identity, and other kinds forbid it')
        if self.archive is not None and self.kind not in ('zip', 'jar', 'apk'):
            raise ValueError('archive policy is valid only for ZIP/JAR/APK artifacts')
        if self.role == 'corresponding-source' and self.apk is not None:
            raise ValueError('corresponding-source artifacts cannot be APK payloads')
        if (
            self.source is not None
            and self.source.corresponding_source_artifact == self.id
        ):
            raise ValueError('an artifact cannot be its own corresponding source')
        if (
            self.role == 'corresponding-source'
            and self.source is not None
            and self.source.corresponding_source_artifact is not None
        ):
            raise ValueError(
                'corresponding-source artifacts cannot link another source artifact'
            )
        if (
            self.legal is not None
            and self.legal.source_offer_required
            and (
                self.source is None
                or self.source.corresponding_source_artifact is None
            )
        ):
            raise ValueError(
                'source-offer-required artifacts require locked corresponding source'
            )
        return self


class ModuleLock(LockModel):
    id: str
    version: NonBlankString
    artifacts: tuple[ArtifactLock, ...] = Field(min_length=1)

    @field_validator('id')
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid module ID: {value!r}')
        return value

    @model_validator(mode='after')
    def validate_artifacts(self) -> Self:
        ids = [artifact.id for artifact in self.artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError('artifact IDs must be unique within a module')
        if ids != sorted(ids):
            raise ValueError('artifacts must be sorted by canonical ID')
        artifacts = {artifact.id: artifact for artifact in self.artifacts}
        for artifact in self.artifacts:
            artifact_source = artifact.source
            if (
                artifact_source is None
                or artifact_source.corresponding_source_artifact is None
            ):
                continue
            source_id = artifact_source.corresponding_source_artifact
            source = artifacts.get(source_id)
            if source is None:
                raise ValueError(
                    f'artifact {artifact.id!r} references missing corresponding '
                    f'source artifact {source_id!r}'
                )
            if source.role != 'corresponding-source':
                raise ValueError(
                    f'artifact {source_id!r} must have corresponding-source role'
                )
            if source.version != artifact_source.revision:
                raise ValueError(
                    f'artifact {source_id!r} version must match the locked source '
                    'revision'
                )
        return self


class ArtifactLockFile(LockModel):
    schema_version: Literal[1]
    modules: tuple[ModuleLock, ...] = Field(min_length=1)

    @model_validator(mode='after')
    def validate_modules(self) -> Self:
        ids = [module.id for module in self.modules]
        if len(ids) != len(set(ids)):
            raise ValueError('module lock IDs must be unique')
        if ids != sorted(ids):
            raise ValueError('module locks must be sorted by canonical ID')
        return self

    def as_json(self) -> str:
        return json.dumps(
            self.model_dump(mode='json'),
            indent=2,
            sort_keys=True,
        ) + '\n'

    def _as_legacy_v1_json(self) -> str | None:
        """Return pre-extension canonical JSON when no v2 lock fields are used."""

        data = self.model_dump(mode='json')
        for module, module_data in zip(self.modules, data['modules'], strict=True):
            for artifact, artifact_data in zip(
                module.artifacts,
                module_data['artifacts'],
                strict=True,
            ):
                if (
                    artifact.role != 'injection-input'
                    or artifact.source is not None
                    or artifact.legal is not None
                ):
                    return None
                artifact_data.pop('role')
                artifact_data.pop('source')
                artifact_data.pop('legal')
                archive = artifact.archive
                if archive is None:
                    continue
                for member, member_data in zip(
                    archive.members,
                    artifact_data['archive']['members'],
                    strict=True,
                ):
                    if member.apk is not None:
                        return None
                    member_data.pop('apk')
        return json.dumps(data, indent=2, sort_keys=True) + '\n'


def _read_lock_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LockError(f'artifact lock cannot be opened safely: {path}') from error
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise LockError(f'artifact lock is not a regular file: {path}')
        if metadata.st_size > MAX_LOCK_FILE_BYTES:
            raise LockError(f'artifact lock exceeds the byte limit: {path}')
        data = source.read(MAX_LOCK_FILE_BYTES + 1)
        if len(data) > MAX_LOCK_FILE_BYTES:
            raise LockError(f'artifact lock exceeds the byte limit: {path}')
        return data


def _parse_lock(path: Path, data: bytes) -> ArtifactLockFile:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'duplicate JSON object key: {key!r}')
            result[key] = value
        return result

    try:
        raw = json.loads(
            data.decode('UTF-8'),
            object_pairs_hook=reject_duplicate_keys,
        )
        return ArtifactLockFile.model_validate(raw)
    except Exception as error:
        # Validation errors may echo unsafe URL queries or other raw lock values.
        raise LockError(f'invalid artifact lock: {path}') from error


def load_lock(path: Path) -> ArtifactLockFile:
    return _parse_lock(path, _read_lock_bytes(path))


def load_canonical_lock(path: Path) -> tuple[ArtifactLockFile, str]:
    """Load one bounded canonical lock and return its actual byte digest."""

    data = _read_lock_bytes(path)
    lock = _parse_lock(path, data)
    canonical = lock.as_json().encode('UTF-8')
    legacy = lock._as_legacy_v1_json()
    if data != canonical and (
        legacy is None or data != legacy.encode('UTF-8')
    ):
        raise LockError('artifact lock is valid but not canonical JSON')
    return lock, hashlib.sha256(data).hexdigest()


def write_lock(path: Path, lock: ArtifactLockFile) -> None:
    """Write a canonical lock with fsync and atomic replacement."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f'.{path.name}.',
        suffix='.tmp',
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'w', encoding='UTF-8', newline='\n') as output:
            output.write(lock.as_json())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def cache_path(cache_dir: Path, digest: str) -> Path:
    if not SHA256_PATTERN.fullmatch(digest):
        raise LockError('invalid cache digest')
    return cache_dir / 'sha256' / digest[:2] / digest


@contextmanager
def open_verified_cached_artifact(
    artifact: ArtifactLock,
    cache_dir: Path,
) -> Iterator[BinaryIO]:
    path = cache_path(cache_dir, artifact.sha256)
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise LockError(f'cached artifact is missing: {artifact.id}') from error
    except OSError as error:
        raise LockError(f'cached artifact cannot be opened safely: {artifact.id}') from error
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LockError(f'cached artifact is not a regular file: {artifact.id}')
        if metadata.st_size != artifact.size:
            raise LockError(f'cached artifact has the wrong size: {artifact.id}')
        digest = hashlib.sha256()
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != artifact.sha256:
            raise LockError(f'cached artifact has the wrong SHA-256: {artifact.id}')
        source.seek(0)
        yield source


def verify_cached_artifact(artifact: ArtifactLock, cache_dir: Path) -> Path:
    with open_verified_cached_artifact(artifact, cache_dir):
        pass
    return cache_path(cache_dir, artifact.sha256)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_download_destination(artifact: ArtifactLock, value: str) -> None:
    try:
        _validate_public_https_url(value)
    except ValueError as error:
        raise LockError(f'download redirected outside safe HTTPS: {artifact.id}') from error
    if _url_origin(value) not in {
        _url_origin(origin) for origin in artifact.allowed_origins
    }:
        raise LockError(f'download redirected outside allowed origins: {artifact.id}')


class _ArtifactRedirectHandler(HTTPRedirectHandler):
    def __init__(self, artifact: ArtifactLock) -> None:
        self.artifact = artifact
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # HTTPRedirectHandler calls this before issuing the redirected request.
        _validate_download_destination(self.artifact, newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download_https(artifact: ArtifactLock, output) -> None:
    try:
        request = Request(
            artifact.immutable_url,
            headers={'User-Agent': 'my-avbroot-setup-lock-fetch/1'},
        )
        opener = build_opener(_ArtifactRedirectHandler(artifact))
        with opener.open(request, timeout=60) as response:
            _validate_download_destination(artifact, response.geturl())
            content_encoding = response.headers.get('Content-Encoding', 'identity')
            if content_encoding.lower() != 'identity':
                raise LockError(
                    f'download used a forbidden content encoding: {artifact.id}'
                )
            content_length = response.headers.get('Content-Length')
            if content_length is not None:
                try:
                    declared_length = int(content_length, 10)
                except ValueError as error:
                    raise LockError('download returned an invalid Content-Length') from error
                if declared_length != artifact.size:
                    raise LockError(
                        f'download Content-Length differs from lock: {artifact.id}'
                    )
            shutil.copyfileobj(response, output, length=64 * 1024)
    except LockError:
        raise
    except Exception as error:
        # Network exceptions often include the complete URL. Keep diagnostics
        # bounded to the reviewed artifact ID so query data is never exposed.
        raise LockError(f'artifact download failed: {artifact.id}') from error


DownloadFunction = Callable[[ArtifactLock, object], None]


def fetch_artifact(
    artifact: ArtifactLock,
    cache_dir: Path,
    *,
    downloader: DownloadFunction = _download_https,
) -> Path:
    """Fetch one locked object through a bounded temporary file into the cache."""

    target = cache_path(cache_dir, artifact.sha256)
    directories = (cache_dir, cache_dir / 'sha256', target.parent)
    for index, directory in enumerate(directories):
        directory.mkdir(mode=0o700, parents=index == 0, exist_ok=True)
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise LockError(f'cache path is not a real directory: {directory}')
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    else:
        return verify_cached_artifact(artifact, cache_dir)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f'.{artifact.sha256}.',
        suffix='.tmp',
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        digest = hashlib.sha256()
        written = 0
        with os.fdopen(descriptor, 'wb', buffering=0) as raw:
            class BoundedWriter:
                def write(self, data: bytes) -> int:
                    nonlocal written
                    view = memoryview(data).cast('B')
                    if written + len(view) > artifact.size:
                        raise LockError(f'download exceeded locked size: {artifact.id}')
                    consumed = 0
                    while consumed < len(view):
                        count = raw.write(view[consumed:])
                        if not count:
                            raise LockError(f'download cache write made no progress: {artifact.id}')
                        digest.update(view[consumed:consumed + count])
                        written += count
                        consumed += count
                    return consumed

                def flush(self) -> None:
                    raw.flush()

            writer = BoundedWriter()
            downloader(artifact, writer)
            writer.flush()
            os.fsync(raw.fileno())
            os.fchmod(raw.fileno(), 0o444)
        if written != artifact.size:
            raise LockError(f'download has the wrong size: {artifact.id}')
        if digest.hexdigest() != artifact.sha256:
            raise LockError(f'download has the wrong SHA-256: {artifact.id}')
        os.replace(temporary, target)
        _fsync_directory(target.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return verify_cached_artifact(artifact, cache_dir)


def iter_artifacts(
    lock: ArtifactLockFile,
    module_ids: Iterable[str] | None = None,
) -> Iterable[ArtifactLock]:
    selected = set(module_ids) if module_ids is not None else None
    known = {module.id for module in lock.modules}
    if selected is not None and selected - known:
        raise LockError(
            f'lock does not contain modules: {", ".join(sorted(selected - known))}'
        )
    for module in lock.modules:
        if selected is None or module.id in selected:
            yield from module.artifacts


def fetch_locked_artifacts(
    lock: ArtifactLockFile,
    cache_dir: Path,
    *,
    module_ids: Iterable[str] | None = None,
    downloader: DownloadFunction = _download_https,
) -> tuple[Path, ...]:
    return tuple(
        fetch_artifact(artifact, cache_dir, downloader=downloader)
        for artifact in iter_artifacts(lock, module_ids)
    )


def _run_identity_command(
    arguments: list[str],
    *,
    pass_fds: tuple[int, ...] = (),
) -> str:
    try:
        return subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'},
            pass_fds=pass_fds,
        ).stdout
    except FileNotFoundError as error:
        raise LockError(f'required verifier is unavailable: {arguments[0]}') from error
    except subprocess.CalledProcessError as error:
        raise LockError(f'artifact identity verification failed: {arguments[0]}') from error


def verify_apk_identity(
    path: Path,
    expected: ApkIdentity,
    *,
    pass_fds: tuple[int, ...] = (),
) -> None:
    signature_output = _run_identity_command(
        ['apksigner', 'verify', '--verbose', '--print-certs', str(path)],
        pass_fds=pass_fds,
    )
    signer_matches = re.findall(
        r'^Signer #\d+ certificate SHA-256 digest: ([0-9A-Fa-f:]+)$',
        signature_output,
        flags=re.MULTILINE,
    )
    signers = tuple(value.replace(':', '').lower() for value in signer_matches)
    if signers != (expected.signer_sha256,):
        raise LockError('APK signer does not match the single locked signer')

    package_name = _run_identity_command(
        ['apkanalyzer', 'manifest', 'application-id', str(path)],
        pass_fds=pass_fds,
    ).strip()
    version_text = _run_identity_command(
        ['apkanalyzer', 'manifest', 'version-code', str(path)],
        pass_fds=pass_fds,
    ).strip()
    try:
        version_code = int(version_text, 10)
    except ValueError as error:
        raise LockError('apkanalyzer returned an invalid versionCode') from error
    if package_name != expected.package_name or version_code != expected.version_code:
        raise LockError('APK package name or versionCode does not match the lock')


def verify_locked_artifacts(
    lock: ArtifactLockFile,
    cache_dir: Path,
    *,
    module_ids: Iterable[str] | None = None,
    verify_apks: bool = True,
) -> tuple[Path, ...]:
    verified: list[Path] = []
    for artifact in iter_artifacts(lock, module_ids):
        path = cache_path(cache_dir, artifact.sha256)
        with open_verified_cached_artifact(artifact, cache_dir) as source:
            descriptor = source.fileno()
            verified_path = Path(f'/proc/self/fd/{descriptor}')
            if artifact.archive is not None:
                inspection = inspect_zip(
                    verified_path,
                    allowlisted_members=artifact.archive.allowlisted_members,
                    limits=artifact.archive.limits(),
                )
                inspected = {member.name: member for member in inspection.members}
                apk_members = tuple(
                    expected.name for expected in artifact.archive.members
                    if verify_apks and expected.apk is not None
                )
                member_data = read_allowlisted_members(
                    verified_path,
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
                        # Keep nested APK verification capability-based too: the
                        # verifier sees an anonymous descriptor containing bytes
                        # read from the already verified outer archive inode, not
                        # a cache pathname that can be replaced concurrently.
                        with tempfile.TemporaryFile() as nested_apk:
                            nested_apk.write(data)
                            nested_apk.flush()
                            nested_descriptor = nested_apk.fileno()
                            verify_apk_identity(
                                Path(f'/proc/self/fd/{nested_descriptor}'),
                                expected.apk,
                                pass_fds=(nested_descriptor,),
                            )
            if verify_apks and artifact.apk is not None:
                verify_apk_identity(
                    verified_path,
                    artifact.apk,
                    pass_fds=(descriptor,),
                )
        verified.append(path)
    return tuple(verified)
