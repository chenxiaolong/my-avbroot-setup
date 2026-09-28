# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Fail-closed compatibility and output-policy resolution."""

from collections import Counter
from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Annotated, ClassVar, Literal, Self

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
import tomlkit

from lib.modules.catalog import (
    COMPATIBILITY_TOKEN_PATTERN,
    ModuleCatalog,
    ModuleSpec,
)
from lib.modules.locks import ArtifactLockFile, SHA256_PATTERN
from lib.modules.registry import MODULE_ID_PATTERN


NonBlankString = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, pattern=r'.*\S.*'),
]


class ResolutionError(ValueError):
    """A profile is ambiguous, unsupported, or violates catalog policy."""


class ResolverModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra='forbid', frozen=True)


class ObservedCapabilities(ResolverModel):
    root_providers: tuple[Literal['magisk', 'kernelsu', 'apatch'], ...] = ()
    zygisk_providers: tuple[
        Literal['magisk', 'kernelsu', 'apatch', 'zygisk-next'],
        ...,
    ] = ()
    selective_signature_spoofing: StrictBool = False
    product_priv_app: StrictBool = False
    custom_init_selinux: StrictBool = False

    @field_validator('root_providers', 'zygisk_providers')
    @classmethod
    def validate_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError('observed providers must be unique')
        return values


class CriticalAcknowledgement(ResolverModel):
    module: NonBlankString
    lock_sha256: str
    output_scope: Literal['local-unpublished', 'private', 'shared', 'published']

    @field_validator('module')
    @classmethod
    def validate_module(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError('invalid acknowledged module ID')
        return value

    @field_validator('lock_sha256')
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not SHA256_PATTERN.fullmatch(value):
            raise ValueError('acknowledgement lock digest must be lowercase SHA-256')
        return value


class ExperimentalAcknowledgement(ResolverModel):
    """Affirmative consent bound to the exact experimental catalog policy."""

    module: NonBlankString
    lock_sha256: str
    output_scope: Literal['local-unpublished', 'private', 'shared', 'published']
    acknowledgement: NonBlankString

    @field_validator('module')
    @classmethod
    def validate_module(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError('invalid acknowledged experimental module ID')
        return value

    @field_validator('lock_sha256')
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not SHA256_PATTERN.fullmatch(value):
            raise ValueError(
                'experimental acknowledgement lock digest must be lowercase SHA-256'
            )
        return value


class ResolutionProfile(ResolverModel):
    schema_version: Literal[1]
    id: NonBlankString
    rom_family: NonBlankString
    root_mode: Literal['rootless', 'rooted']
    abi: NonBlankString
    api_level: StrictInt = Field(ge=1)
    output_scope: Literal['local-unpublished', 'private', 'shared', 'published']
    enabled_modules: tuple[NonBlankString, ...]
    capabilities: ObservedCapabilities
    acknowledgements: tuple[CriticalAcknowledgement, ...] = ()
    experimental_acknowledgements: tuple[ExperimentalAcknowledgement, ...] = ()

    @field_validator('id', 'rom_family', 'abi')
    @classmethod
    def validate_tokens(cls, value: str) -> str:
        if not COMPATIBILITY_TOKEN_PATTERN.fullmatch(value):
            raise ValueError(f'invalid profile token: {value!r}')
        return value

    @field_validator('enabled_modules')
    @classmethod
    def validate_modules(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not MODULE_ID_PATTERN.fullmatch(value):
                raise ValueError(f'invalid enabled module ID: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('enabled module IDs must be unique')
        return values

    @model_validator(mode='after')
    def validate_acknowledgements(self) -> Self:
        modules = [item.module for item in self.acknowledgements]
        if len(modules) != len(set(modules)):
            raise ValueError('critical acknowledgements must be unique by module')
        experimental_modules = [
            item.module for item in self.experimental_acknowledgements
        ]
        if len(experimental_modules) != len(set(experimental_modules)):
            raise ValueError('experimental acknowledgements must be unique by module')
        return self


class CompatibilityDecision(ResolverModel):
    module: str
    rom_status: Literal['supported', 'experimental']
    reason: Mapping[str, str] | None
    warnings: tuple[Mapping[str, str], ...]


class Resolution:
    def __init__(
        self,
        profile: ResolutionProfile,
        decisions: tuple[CompatibilityDecision, ...],
        lock_sha256: str,
        fingerprint: str,
    ) -> None:
        self.profile = profile
        self.decisions = decisions
        self.lock_sha256 = lock_sha256
        self.fingerprint = fingerprint

    @property
    def selected_modules(self) -> tuple[str, ...]:
        return tuple(decision.module for decision in self.decisions)

    def as_dict(self) -> dict[str, object]:
        return {
            'schema_version': 1,
            'profile': self.profile.id,
            'rom_family': self.profile.rom_family,
            'output_scope': self.profile.output_scope,
            'lock_sha256': self.lock_sha256,
            'selected_modules': list(self.selected_modules),
            'decisions': [
                decision.model_dump(mode='json') for decision in self.decisions
            ],
            'fingerprint': self.fingerprint,
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True) + '\n'

    def as_text(self) -> str:
        lines = ['MODULE\tROM STATUS\tWARNINGS']
        for decision in self.decisions:
            lines.append(
                f'{decision.module}\t{decision.rom_status}\t'
                f'{len(decision.warnings)}'
            )
        lines.append(f'FINGERPRINT\t{self.fingerprint}')
        return '\n'.join(lines) + '\n'


def load_profile(path: Path) -> ResolutionProfile:
    try:
        raw = tomlkit.loads(path.read_text(encoding='UTF-8')).unwrap()
        return ResolutionProfile.model_validate(raw)
    except Exception as error:
        # Validation errors include raw input values. Keep profile diagnostics
        # generic so unknown fields cannot disclose secrets or inject output.
        raise ResolutionError(f'invalid resolution profile: {path}') from error


def _provider_available(
    requirement: str | None,
    available: set[str],
    kind: str,
) -> None:
    if requirement is None:
        return
    if requirement == 'any':
        if len(available) != 1:
            raise ResolutionError(
                f'{kind} provider requirement is ambiguous: {sorted(available)}'
            )
    elif requirement not in available:
        raise ResolutionError(f'required {kind} provider is unavailable: {requirement}')


def _require_module_capabilities(
    module: ModuleSpec,
    profile: ResolutionProfile,
    root_providers: set[str],
    zygisk_providers: set[str],
    selective_signature_spoofing: bool,
    product_priv_app: bool,
    custom_init_selinux: bool,
) -> None:
    requirements = module.capabilities.requires
    _provider_available(requirements.root_provider, root_providers, 'root')
    _provider_available(requirements.zygisk_provider, zygisk_providers, 'Zygisk')
    boolean_requirements = (
        (
            'selective signature spoofing',
            requirements.selective_signature_spoofing,
            selective_signature_spoofing,
        ),
        ('product priv-app', requirements.product_priv_app, product_priv_app),
        (
            'custom init/SELinux',
            requirements.custom_init_selinux,
            custom_init_selinux,
        ),
    )
    for name, required, present in boolean_requirements:
        if required and not present:
            raise ResolutionError(
                f'{module.id} requires unavailable capability: {name}'
            )

    if 'unknown' in requirements.abis:
        raise ResolutionError(f'{module.id} has unknown ABI requirements')
    if 'any' not in requirements.abis and profile.abi not in requirements.abis:
        raise ResolutionError(f'{module.id} does not support ABI: {profile.abi}')
    if requirements.min_api is not None and profile.api_level < requirements.min_api:
        raise ResolutionError(f'{module.id} requires API >= {requirements.min_api}')
    if requirements.max_api is not None and profile.api_level > requirements.max_api:
        raise ResolutionError(f'{module.id} requires API <= {requirements.max_api}')


def _detect_dependency_cycles(modules: dict[str, ModuleSpec]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(module_id: str) -> None:
        if module_id in visiting:
            cycle_start = stack.index(module_id)
            cycle = stack[cycle_start:] + [module_id]
            raise ResolutionError(f'dependency cycle: {" -> ".join(cycle)}')
        if module_id in visited:
            return
        visiting.add(module_id)
        stack.append(module_id)
        for dependency in sorted(modules[module_id].dependencies):
            if dependency in modules:
                visit(dependency)
        stack.pop()
        visiting.remove(module_id)
        visited.add(module_id)

    for module_id in sorted(modules):
        visit(module_id)


def _canonical_profile(profile: ResolutionProfile) -> dict[str, object]:
    """Return the semantic profile data used by the stable fingerprint.

    Profile tuple fields are sets by contract.  Their input ordering must not
    create distinct release names for an otherwise identical selection.
    """

    data = profile.model_dump(mode='json')
    data['enabled_modules'] = sorted(data['enabled_modules'])
    capabilities = data['capabilities']
    capabilities['root_providers'] = sorted(capabilities['root_providers'])
    capabilities['zygisk_providers'] = sorted(capabilities['zygisk_providers'])
    data['acknowledgements'] = sorted(
        data['acknowledgements'],
        key=lambda acknowledgement: acknowledgement['module'],
    )
    data['experimental_acknowledgements'] = sorted(
        data['experimental_acknowledgements'],
        key=lambda acknowledgement: acknowledgement['module'],
    )
    return data


def resolve_profile(
    catalog: ModuleCatalog,
    profile: ResolutionProfile,
    lock: ArtifactLockFile,
    lock_sha256: str,
) -> Resolution:
    # ``lock_sha256`` is the digest of the accepted canonical input bytes, not
    # necessarily ``lock.as_json()``.  The canonical loader also accepts the
    # pre-extension schema-v1 representation and returns its actual byte
    # digest.  Keep canonical-byte validation at that I/O boundary; this
    # pure resolver validates and consumes the paired digest as authoritative.
    if not SHA256_PATTERN.fullmatch(lock_sha256):
        raise ResolutionError('actual lock digest must be lowercase SHA-256')
    if profile.rom_family == 'unknown':
        raise ResolutionError('profile ROM family is unknown')
    if profile.abi == 'unknown':
        raise ResolutionError('profile ABI capability is unknown')

    catalog_ids = [module.id for module in catalog.modules]
    duplicate_ids = {
        module_id
        for module_id, count in Counter(catalog_ids).items()
        if count > 1
    }
    if duplicate_ids:
        raise ResolutionError(
            'catalog contains duplicate module IDs: '
            f'{", ".join(sorted(duplicate_ids))}'
        )
    by_id = {module.id: module for module in catalog.modules}
    requested = set(profile.enabled_modules)
    unknown = requested - set(by_id)
    if unknown:
        raise ResolutionError(
            'profile selects unknown modules: '
            f'{", ".join(sorted(unknown))}'
        )
    locked = {module.id for module in lock.modules}
    missing_from_lock = requested - locked
    if missing_from_lock:
        raise ResolutionError(
            'selected modules are absent from the artifact lock: '
            f'{", ".join(sorted(missing_from_lock))}'
        )

    selected = {module_id: by_id[module_id] for module_id in sorted(requested)}
    _detect_dependency_cycles(selected)
    for module in selected.values():
        missing = set(module.dependencies) - requested
        if missing:
            raise ResolutionError(
                f'{module.id} has unselected dependencies: {", ".join(sorted(missing))}'
            )
        conflicts = set(module.conflicts) & requested
        reverse_conflicts = {
            other.id for other in selected.values() if module.id in other.conflicts
        }
        conflicts |= reverse_conflicts
        if conflicts:
            raise ResolutionError(
                f'{module.id} conflicts with selected modules: '
                f'{", ".join(sorted(conflicts))}'
            )

    acknowledgements = {item.module: item for item in profile.acknowledgements}
    unused_acknowledgements = set(acknowledgements) - requested
    if unused_acknowledgements:
        raise ResolutionError(
            'acknowledgements reference unselected modules: '
            f'{", ".join(sorted(unused_acknowledgements))}'
        )
    unnecessary_acknowledgements = {
        module_id
        for module_id in acknowledgements
        if not selected[module_id].acknowledgement_required
    }
    if unnecessary_acknowledgements:
        raise ResolutionError(
            'acknowledgements supplied for modules that do not require them: '
            f'{", ".join(sorted(unnecessary_acknowledgements))}'
        )
    experimental_acknowledgements = {
        item.module: item for item in profile.experimental_acknowledgements
    }
    unused_experimental_acknowledgements = (
        set(experimental_acknowledgements) - requested
    )
    if unused_experimental_acknowledgements:
        raise ResolutionError(
            'experimental acknowledgements reference unselected modules: '
            f'{", ".join(sorted(unused_experimental_acknowledgements))}'
        )
    unnecessary_experimental_acknowledgements = {
        module_id
        for module_id in experimental_acknowledgements
        if selected[module_id].status != 'experimental'
        or selected[module_id].experimental_opt_in is None
    }
    if unnecessary_experimental_acknowledgements:
        raise ResolutionError(
            'experimental acknowledgements supplied for modules without an '
            'experimental opt-in policy: '
            f'{", ".join(sorted(unnecessary_experimental_acknowledgements))}'
        )

    decisions: list[CompatibilityDecision] = []
    for module_id in sorted(selected):
        module = selected[module_id]
        if module.status == 'incompatible':
            raise ResolutionError(f'{module.id} is globally incompatible')
        if module.status == 'experimental':
            policy = module.experimental_opt_in
            if policy is None:
                raise ResolutionError(
                    f'{module.id} has no experimental opt-in policy and cannot '
                    'be selected'
                )
            acknowledgement = experimental_acknowledgements.get(module.id)
            if acknowledgement is None:
                raise ResolutionError(
                    f'{module.id} requires an explicit experimental acknowledgement'
                )
            if (
                acknowledgement.lock_sha256 != lock_sha256
                or acknowledgement.output_scope != profile.output_scope
                or acknowledgement.acknowledgement != policy.acknowledgement
            ):
                raise ResolutionError(
                    f'{module.id} experimental acknowledgement is stale or wrong'
                )

        rom = module.compatibility.roms.get(profile.rom_family)
        if rom is None:
            rom = module.compatibility.roms.get('any')
        if rom is None:
            raise ResolutionError(
                f'{module.id} has no known status for {profile.rom_family}'
            )
        if rom.status == 'incompatible':
            raise ResolutionError(
                f'{module.id} is incompatible with {profile.rom_family}'
            )

        if 'unknown' in module.compatibility.root_modes:
            raise ResolutionError(f'{module.id} has unknown root-mode compatibility')
        if 'any' not in module.compatibility.root_modes and (
            profile.root_mode not in module.compatibility.root_modes
        ):
            raise ResolutionError(f'{module.id} does not support {profile.root_mode}')
        if 'unknown' in module.compatibility.architectures:
            raise ResolutionError(f'{module.id} has unknown architecture compatibility')
        if 'any' not in module.compatibility.architectures and (
            profile.abi not in module.compatibility.architectures
        ):
            raise ResolutionError(
                f'{module.id} does not support architecture {profile.abi}'
            )

        if profile.output_scope not in module.legal.allowed_output_scopes:
            raise ResolutionError(
                f'{module.id} forbids output scope: {profile.output_scope}'
            )
        # Selected modules may provide capabilities to one another, but a
        # module cannot satisfy its own prerequisite merely by claiming that
        # it will provide the same capability after installation.
        dependency_modules = tuple(
            selected[dependency]
            for dependency in sorted(module.dependencies)
            if dependency in selected
        )
        root_providers: set[str] = set(profile.capabilities.root_providers)
        zygisk_providers: set[str] = set(profile.capabilities.zygisk_providers)
        for other in dependency_modules:
            root_providers.update(other.capabilities.provides.root)
            zygisk_providers.update(other.capabilities.provides.zygisk)
        _require_module_capabilities(
            module,
            profile,
            root_providers,
            zygisk_providers,
            profile.capabilities.selective_signature_spoofing or any(
                other.capabilities.provides.selective_signature_spoofing
                for other in dependency_modules
            ),
            profile.capabilities.product_priv_app or any(
                other.capabilities.provides.product_priv_app
                for other in dependency_modules
            ),
            profile.capabilities.custom_init_selinux or any(
                other.capabilities.provides.custom_init_selinux
                for other in dependency_modules
            ),
        )

        if module.acknowledgement_required:
            acknowledgement = acknowledgements.get(module.id)
            if acknowledgement is None:
                raise ResolutionError(
                    f'{module.id} requires a lock-bound acknowledgement'
                )
            if (
                acknowledgement.lock_sha256 != lock_sha256
                or acknowledgement.output_scope != profile.output_scope
            ):
                raise ResolutionError(
                    f'{module.id} acknowledgement is stale or wrong-scope'
                )

        reason = rom.reason.model_dump(mode='json') if rom.reason else None
        warnings = tuple(
            warning.model_dump(mode='json') for warning in module.warnings
        )
        decisions.append(CompatibilityDecision(
            module=module.id,
            rom_status=rom.status,
            reason=reason,
            warnings=warnings,
        ))

    fingerprint_input = {
        'schema_version': 1,
        'lock_sha256': lock_sha256,
        'profile': _canonical_profile(profile),
        'modules': [
            selected[module_id].model_dump(mode='json')
            for module_id in sorted(selected)
        ],
        'selected': [decision.model_dump(mode='json') for decision in decisions],
    }
    fingerprint = hashlib.sha256(json.dumps(
        fingerprint_input,
        sort_keys=True,
        separators=(',', ':'),
    ).encode('UTF-8')).hexdigest()
    return Resolution(profile, tuple(decisions), lock_sha256, fingerprint)
