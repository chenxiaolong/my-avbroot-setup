# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Declarative catalog for image-native patch modules.

Catalog loading is intentionally data-only. Adapter identifiers are resolved by
``lib.modules.all_modules()`` through a static internal registry; manifests can
never name an arbitrary Python object to import.

Schema v1 manifests are validated as v1 before a deterministic, conservative
migration to the canonical schema v2 model. Catalog consumers therefore only
need to understand v2, while existing checked-in and downstream manifests keep
loading unchanged.
"""

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import re
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

from lib.modules.licenses import LICENSE_PATTERN
from lib.modules.registry import (
    AdapterRegistration,
    INTERNAL_ADAPTERS,
    LOCKED_ADAPTERS,
    MODULE_ID_PATTERN,
)


COMPATIBILITY_TOKEN_PATTERN = re.compile(r'^[a-z][a-z0-9_-]*$')
MANIFESTS_DIR = Path(__file__).with_name('manifests')
StrictString = Annotated[str, StringConstraints(strict=True)]
NonBlankString = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, pattern=r'.*\S.*'),
]
ApiLevel = Annotated[StrictInt, Field(ge=1)]

ModuleStatus = Literal['supported', 'experimental', 'incompatible']
Lifecycle = Literal[
    'static-image',
    'custom-init',
    'root-runtime',
    'first-boot-provisioned',
    'external-reference',
    'user-direct-install',
]
TrustRootType = Literal[
    'x509-cert-sha256',
    'apk-signer-sha256',
    'openpgp-primary',
    'openpgp-subkey',
    'ssh-key-sha256',
    'github-attestation',
]
RootProvider = Literal['magisk', 'kernelsu', 'apatch']
ZygiskProvider = Literal['magisk', 'kernelsu', 'apatch', 'zygisk-next']


class CatalogError(ValueError):
    """The module catalog is incomplete, ambiguous, or unsafe to load."""


class CatalogModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra='forbid',
        frozen=True,
    )


class Reason(CatalogModel):
    code: StrictString
    message: NonBlankString

    @field_validator('code')
    @classmethod
    def validate_code(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid reason code: {value!r}')
        return value


class Warning(CatalogModel):
    code: StrictString
    severity: Literal['info', 'warning', 'critical']
    message: NonBlankString

    @field_validator('code')
    @classmethod
    def validate_code(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid warning code: {value!r}')
        return value


class TrustRoot(CatalogModel):
    type: TrustRootType
    value: NonBlankString

    @model_validator(mode='after')
    def validate_fingerprint(self) -> Self:
        compact = self.value.replace(':', '')
        if self.type in {'x509-cert-sha256', 'apk-signer-sha256'}:
            if not re.fullmatch(r'[0-9A-Fa-f]{64}', compact):
                raise ValueError(f'{self.type} requires exactly 64 hexadecimal digits')
        elif self.type in {'openpgp-primary', 'openpgp-subkey'}:
            if not re.fullmatch(r'[0-9A-Fa-f]{40}', compact):
                raise ValueError(f'{self.type} requires a full 40-digit fingerprint')
        return self


class VerificationPolicy(CatalogModel):
    schemes: tuple[
        Literal[
            'sha256',
            'ssh-signature',
            'apk-signature',
            'jar-signature',
            'openpgp-signature',
            'github-attestation',
            'none',
        ],
        ...,
    ] = Field(min_length=1)
    trust_roots: tuple[TrustRoot, ...] = ()
    digest_required: StrictBool = False
    enforced_by: Literal['adapter']

    @model_validator(mode='after')
    def validate_policy(self) -> Self:
        if len(self.schemes) != len(set(self.schemes)):
            raise ValueError('verification schemes must be unique')
        roots = [(root.type, root.value) for root in self.trust_roots]
        if len(roots) != len(set(roots)):
            raise ValueError('typed trust roots must be unique')
        if 'none' in self.schemes and len(self.schemes) != 1:
            raise ValueError('verification scheme "none" cannot be combined')
        if 'none' in self.schemes and self.trust_roots:
            raise ValueError('verification scheme "none" cannot have trust roots')
        if self.digest_required and 'sha256' not in self.schemes:
            raise ValueError('digest_required requires the sha256 scheme')

        required_roots: dict[str, set[str]] = {
            'ssh-signature': {'ssh-key-sha256'},
            'apk-signature': {'apk-signer-sha256'},
            'jar-signature': {'x509-cert-sha256'},
            'openpgp-signature': {'openpgp-primary', 'openpgp-subkey'},
            'github-attestation': {'github-attestation'},
        }
        root_types = {root.type for root in self.trust_roots}
        for scheme, accepted_types in required_roots.items():
            if scheme in self.schemes and not accepted_types.issubset(root_types):
                raise ValueError(f'{scheme} requires all matching typed trust roots')

        allowed_types: set[str] = set()
        for scheme in self.schemes:
            allowed_types |= required_roots.get(scheme, set())
        unexpected = root_types - allowed_types
        if unexpected:
            raise ValueError(
                'typed trust roots have no matching verification scheme: '
                f'{", ".join(sorted(unexpected))}'
            )
        return self

    @property
    def trusted_signer_values(self) -> tuple[str, ...]:
        """Compatibility bridge for the current static adapter registry."""

        return tuple(root.value for root in self.trust_roots)


class RomCompatibility(CatalogModel):
    status: ModuleStatus
    reason: Reason | None = None

    @model_validator(mode='after')
    def validate_status(self) -> Self:
        if self.status != 'supported' and self.reason is None:
            raise ValueError(
                'experimental and incompatible ROM statuses require a reason'
            )
        return self


class Compatibility(CatalogModel):
    roms: Mapping[StrictString, RomCompatibility] = Field(min_length=1)
    root_modes: tuple[
        Literal['rootless', 'rooted', 'any', 'unknown'],
        ...,
    ] = Field(min_length=1)
    architectures: tuple[StrictString, ...] = Field(min_length=1)

    @field_validator('roms')
    @classmethod
    def validate_roms(
        cls,
        values: Mapping[str, RomCompatibility],
    ) -> Mapping[str, RomCompatibility]:
        for value in values:
            if value not in {'any', 'unknown'} and not (
                COMPATIBILITY_TOKEN_PATTERN.fullmatch(value)
            ):
                raise ValueError(f'invalid ROM family token: {value!r}')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole ROM family')
        return values

    @field_validator('architectures')
    @classmethod
    def validate_architectures(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if value != 'any' and value != 'unknown' and not (
                COMPATIBILITY_TOKEN_PATTERN.fullmatch(value)
            ):
                raise ValueError(f'invalid compatibility token: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('compatibility tokens must be unique')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole compatibility token')
        return values

    @field_validator('root_modes')
    @classmethod
    def validate_root_modes(
        cls,
        values: tuple[Literal['rootless', 'rooted', 'any', 'unknown'], ...],
    ) -> tuple[Literal['rootless', 'rooted', 'any', 'unknown'], ...]:
        if len(values) != len(set(values)):
            raise ValueError('root modes must be unique')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole compatibility token')
        return values


class CapabilityRequirements(CatalogModel):
    root_provider: RootProvider | Literal['any'] | None = None
    zygisk_provider: ZygiskProvider | Literal['any'] | None = None
    selective_signature_spoofing: StrictBool = False
    product_priv_app: StrictBool = False
    custom_init_selinux: StrictBool = False
    abis: tuple[StrictString, ...] = ('unknown',)
    min_api: ApiLevel | None = None
    max_api: ApiLevel | None = None

    @field_validator('abis')
    @classmethod
    def validate_abis(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError('ABI requirements cannot be empty')
        for value in values:
            if value not in {'any', 'unknown'} and not (
                COMPATIBILITY_TOKEN_PATTERN.fullmatch(value)
            ):
                raise ValueError(f'invalid ABI token: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('ABI requirements must be unique')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole ABI requirement')
        return values

    @model_validator(mode='after')
    def validate_api_range(self) -> Self:
        if (
            self.min_api is not None
            and self.max_api is not None
            and self.min_api > self.max_api
        ):
            raise ValueError('min_api cannot exceed max_api')
        return self


class CapabilityProviders(CatalogModel):
    root: tuple[RootProvider, ...] = ()
    zygisk: tuple[ZygiskProvider, ...] = ()
    selective_signature_spoofing: StrictBool = False
    product_priv_app: StrictBool = False
    custom_init_selinux: StrictBool = False

    @field_validator('root', 'zygisk')
    @classmethod
    def validate_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError('provided capabilities must be unique')
        return values


class Capabilities(CatalogModel):
    requires: CapabilityRequirements
    provides: CapabilityProviders


class PermissionRecord(CatalogModel):
    reference: NonBlankString
    source_url: NonBlankString
    granted_scopes: tuple[Literal['private', 'shared', 'published'], ...] = Field(
        min_length=1
    )

    @field_validator('source_url')
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        if not value.startswith('https://'):
            raise ValueError('permission record source_url must use HTTPS')
        return value

    @field_validator('granted_scopes')
    @classmethod
    def validate_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError('permission record scopes must be unique')
        return values


class LegalOutputPolicy(CatalogModel):
    license: NonBlankString
    source_url: NonBlankString | None = None
    source_offer_required: StrictBool
    upstream_only_fetching: StrictBool
    local_only: StrictBool
    cache_policy: Literal['forbidden', 'read-only', 'read-write']
    allowed_output_scopes: tuple[
        Literal['local-unpublished', 'private', 'shared', 'published'],
        ...,
    ] = Field(min_length=1)
    permission_record: PermissionRecord | None = None

    @field_validator('license')
    @classmethod
    def validate_license(cls, value: str) -> str:
        if not LICENSE_PATTERN.fullmatch(value):
            raise ValueError('license must be an SPDX identifier or LicenseRef')
        return value

    @field_validator('source_url')
    @classmethod
    def validate_source_url(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith('https://'):
            raise ValueError('source_url must use HTTPS')
        return value

    @model_validator(mode='after')
    def validate_policy(self) -> Self:
        if len(self.allowed_output_scopes) != len(set(self.allowed_output_scopes)):
            raise ValueError('allowed output scopes must be unique')
        if self.local_only and self.allowed_output_scopes != ('local-unpublished',):
            raise ValueError(
                'local_only requires exactly the local-unpublished output scope'
            )
        if self.upstream_only_fetching and self.source_url is None:
            raise ValueError('upstream-only fetching requires a source URL')
        if self.source_offer_required and self.source_url is None:
            raise ValueError('source-offer requirements require a source URL')
        if (
            {'shared', 'published'} & set(self.allowed_output_scopes)
            and self.permission_record is None
        ):
            raise ValueError(
                'shared or published output requires a permission record'
            )
        if self.permission_record is not None:
            missing = (
                {'shared', 'published'} & set(self.allowed_output_scopes)
            ) - set(self.permission_record.granted_scopes)
            if missing:
                raise ValueError(
                    'permission record does not grant all allowed output scopes'
                )
        return self


class ModuleDefaults(CatalogModel):
    helper_enabled: StrictBool = False
    pixene_profile_enabled: StrictBool = False


class ExperimentalOptInPolicy(CatalogModel):
    """Catalog policy text that a future profile resolver must acknowledge."""

    required: StrictBool
    acknowledgement: NonBlankString

    @field_validator('required')
    @classmethod
    def validate_required(cls, value: bool) -> bool:
        if not value:
            raise ValueError('experimental opt-in policy must be required')
        return value


class ModuleSpec(CatalogModel):
    schema_version: Literal[2]
    id: StrictString
    name: NonBlankString
    status: ModuleStatus
    adapter: StrictString | None = None
    lifecycle: Lifecycle
    defaults: ModuleDefaults
    acknowledgement_required: StrictBool = False
    experimental_opt_in: ExperimentalOptInPolicy | None = None
    artifact_kinds: tuple[
        Literal[
            'native-image-module-zip',
            'magisk-module-zip',
            'recovery-flashable-zip',
            'root-patcher-module-zip',
            'apk',
            'other',
        ],
        ...,
    ] = Field(min_length=1)
    verification: VerificationPolicy
    compatibility: Compatibility
    capabilities: Capabilities
    legal: LegalOutputPolicy
    dependencies: tuple[StrictString, ...] = ()
    conflicts: tuple[StrictString, ...] = ()
    warnings: tuple[Warning, ...] = ()
    reasons: tuple[Reason, ...] = ()

    @property
    def default_enabled(self) -> bool:
        """Retain the v1 helper-default spelling for existing consumers."""

        return self.defaults.helper_enabled

    @field_validator('id')
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid module ID: {value!r}')
        return value

    @field_validator('dependencies', 'conflicts')
    @classmethod
    def validate_module_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not MODULE_ID_PATTERN.fullmatch(value):
                raise ValueError(f'invalid module ID reference: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('module ID references must be unique')
        return values

    @model_validator(mode='after')
    def validate_state(self) -> Self:
        executable_lifecycles = {
            'static-image',
            'custom-init',
            'root-runtime',
            'first-boot-provisioned',
        }
        if (
            self.status == 'supported'
            and self.lifecycle in executable_lifecycles
            and self.adapter is None
        ):
            raise ValueError('supported executable modules require an adapter')
        if self.status == 'incompatible' and self.adapter is not None:
            raise ValueError('incompatible modules cannot register an adapter')
        if (
            self.status == 'experimental'
            and self.adapter is not None
            and self.experimental_opt_in is None
        ):
            raise ValueError(
                'experimental modules with an adapter require an explicit '
                'opt-in acknowledgement policy'
            )
        if self.status != 'experimental' and self.experimental_opt_in is not None:
            raise ValueError(
                'experimental_opt_in is valid only for experimental modules'
            )
        if (
            self.lifecycle in {'external-reference', 'user-direct-install'}
            and self.adapter is not None
        ):
            raise ValueError('non-injected lifecycles cannot register an adapter')
        if self.status != 'supported' and (
            self.defaults.helper_enabled or self.defaults.pixene_profile_enabled
        ):
            raise ValueError('non-supported modules cannot be enabled by default')
        if self.status == 'supported' and 'none' in self.verification.schemes:
            raise ValueError('supported modules require artifact verification')
        if self.status == 'incompatible' and not self.reasons:
            raise ValueError('incompatible modules require a structured reason')
        if len(self.artifact_kinds) != len(set(self.artifact_kinds)):
            raise ValueError('artifact kinds must be unique')
        warning_codes = [warning.code for warning in self.warnings]
        if len(warning_codes) != len(set(warning_codes)):
            raise ValueError('warning codes must be unique')
        reason_codes = [reason.code for reason in self.reasons]
        if len(reason_codes) != len(set(reason_codes)):
            raise ValueError('reason codes must be unique')
        if any(w.severity == 'critical' for w in self.warnings) and not (
            self.acknowledgement_required
        ):
            raise ValueError('critical warnings require acknowledgement')
        if self.acknowledgement_required and (
            self.defaults.helper_enabled or self.defaults.pixene_profile_enabled
        ):
            raise ValueError('acknowledgement-required modules cannot be defaults')
        if self.id in self.dependencies or self.id in self.conflicts:
            raise ValueError('a module cannot depend on or conflict with itself')
        if set(self.dependencies) & set(self.conflicts):
            raise ValueError('a module dependency cannot also be a conflict')
        return self


# Schema v1 models are intentionally private compatibility input. They retain
# the exact original validation rules before migration fills conservative v2
# metadata for fields that did not exist in v1.
class _VerificationPolicyV1(CatalogModel):
    schemes: tuple[
        Literal['sha256', 'ssh-signature', 'apk-signature', 'none'],
        ...,
    ] = Field(min_length=1)
    trusted_signers: tuple[NonBlankString, ...] = ()
    digest_required: StrictBool = False
    enforced_by: Literal['adapter']

    @model_validator(mode='after')
    def validate_policy(self) -> Self:
        if len(self.schemes) != len(set(self.schemes)):
            raise ValueError('verification schemes must be unique')
        if len(self.trusted_signers) != len(set(self.trusted_signers)):
            raise ValueError('trusted signers must be unique')
        if 'none' in self.schemes and len(self.schemes) != 1:
            raise ValueError('verification scheme "none" cannot be combined')
        if 'ssh-signature' in self.schemes and not self.trusted_signers:
            raise ValueError('SSH signature verification requires a trusted signer')
        if self.digest_required and 'sha256' not in self.schemes:
            raise ValueError('digest_required requires the sha256 scheme')
        return self


class _CompatibilityV1(CatalogModel):
    rom_families: tuple[StrictString, ...] = Field(min_length=1)
    root_modes: tuple[
        Literal['rootless', 'rooted', 'any', 'unknown'],
        ...,
    ] = Field(min_length=1)
    architectures: tuple[StrictString, ...] = Field(min_length=1)

    @field_validator('rom_families', 'architectures')
    @classmethod
    def validate_tokens(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if value != 'any' and not COMPATIBILITY_TOKEN_PATTERN.fullmatch(value):
                raise ValueError(f'invalid compatibility token: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('compatibility tokens must be unique')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole compatibility token')
        return values

    @field_validator('root_modes')
    @classmethod
    def validate_root_modes(
        cls,
        values: tuple[Literal['rootless', 'rooted', 'any', 'unknown'], ...],
    ) -> tuple[Literal['rootless', 'rooted', 'any', 'unknown'], ...]:
        if len(values) != len(set(values)):
            raise ValueError('root modes must be unique')
        if ({'any', 'unknown'} & set(values)) and len(values) != 1:
            raise ValueError('any or unknown must be the sole compatibility token')
        return values


class _WarningV1(CatalogModel):
    code: StrictString
    severity: Literal['info', 'warning']
    message: NonBlankString

    @field_validator('code')
    @classmethod
    def validate_code(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid warning code: {value!r}')
        return value


class _ModuleSpecV1(CatalogModel):
    schema_version: Literal[1]
    id: StrictString
    name: NonBlankString
    status: Literal['supported', 'planned', 'incompatible']
    adapter: StrictString | None = None
    default_enabled: StrictBool = False
    artifact_kinds: tuple[
        Literal[
            'native-image-module-zip',
            'magisk-module-zip',
            'recovery-flashable-zip',
            'root-patcher-module-zip',
            'apk',
            'other',
        ],
        ...,
    ] = Field(min_length=1)
    verification: _VerificationPolicyV1
    compatibility: _CompatibilityV1
    dependencies: tuple[StrictString, ...] = ()
    conflicts: tuple[StrictString, ...] = ()
    warnings: tuple[_WarningV1, ...] = ()
    reasons: tuple[Reason, ...] = ()

    @field_validator('id')
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not MODULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f'invalid module ID: {value!r}')
        return value

    @field_validator('dependencies', 'conflicts')
    @classmethod
    def validate_module_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not MODULE_ID_PATTERN.fullmatch(value):
                raise ValueError(f'invalid module ID reference: {value!r}')
        if len(values) != len(set(values)):
            raise ValueError('module ID references must be unique')
        return values

    @model_validator(mode='after')
    def validate_state(self) -> Self:
        if self.status == 'supported' and self.adapter is None:
            raise ValueError('supported modules require an adapter')
        if self.status != 'supported' and self.adapter is not None:
            raise ValueError('non-supported modules cannot register an adapter')
        if self.status != 'supported' and self.default_enabled:
            raise ValueError('non-supported modules cannot be enabled by default')
        if self.status == 'supported' and 'none' in self.verification.schemes:
            raise ValueError('supported modules require artifact verification')
        if self.status == 'incompatible' and not self.reasons:
            raise ValueError('incompatible modules require a structured reason')
        if len(self.artifact_kinds) != len(set(self.artifact_kinds)):
            raise ValueError('artifact kinds must be unique')
        warning_codes = [warning.code for warning in self.warnings]
        if len(warning_codes) != len(set(warning_codes)):
            raise ValueError('warning codes must be unique')
        reason_codes = [reason.code for reason in self.reasons]
        if len(reason_codes) != len(set(reason_codes)):
            raise ValueError('reason codes must be unique')
        if self.id in self.dependencies or self.id in self.conflicts:
            raise ValueError('a module cannot depend on or conflict with itself')
        if set(self.dependencies) & set(self.conflicts):
            raise ValueError('a module dependency cannot also be a conflict')
        return self


def _legacy_lifecycle(spec: _ModuleSpecV1) -> Lifecycle:
    if any(
        kind in {
            'magisk-module-zip',
            'recovery-flashable-zip',
            'root-patcher-module-zip',
        }
        for kind in spec.artifact_kinds
    ):
        return 'root-runtime'
    if 'apk' in spec.artifact_kinds:
        return 'static-image'
    return 'static-image'


def _legacy_trust_root_type(spec: _ModuleSpecV1) -> TrustRootType:
    schemes = set(spec.verification.schemes)
    if 'ssh-signature' in schemes:
        return 'ssh-key-sha256'
    if 'apk-signature' in schemes:
        return 'apk-signer-sha256'
    # v1 had an untyped signer string. X.509 is a deterministic conservative
    # representation for an otherwise ambiguous legacy identity.
    return 'x509-cert-sha256'


def migrate_v1_manifest(raw: Mapping[str, object]) -> dict[str, object]:
    """Validate and deterministically migrate one schema v1 manifest to v2.

    Missing legal and ROM evidence is never promoted to distributable or
    supported metadata: legacy entries receive a local-only LicenseRef and an
    experimental ``unknown`` ROM classification where applicable.
    """

    spec = _ModuleSpecV1.model_validate(raw)
    status: ModuleStatus = (
        'experimental' if spec.status == 'planned' else spec.status
    )
    migration_reason: dict[str, object] = {
        'code': 'legacy-metadata-incomplete',
        'message': 'Schema v1 did not record this compatibility evidence.',
    }
    base_reason: dict[str, object] = (
        spec.reasons[0].model_dump(mode='json')
        if spec.reasons
        else migration_reason
    )
    roms: dict[str, object] = {}
    for family in spec.compatibility.rom_families:
        rom_status: ModuleStatus
        reason: dict[str, object] | None = None
        if family == 'unknown' and status == 'supported':
            rom_status = 'experimental'
            reason = migration_reason
        else:
            rom_status = status
            if rom_status != 'supported':
                reason = base_reason
        rom_entry: dict[str, object] = {'status': rom_status}
        if reason is not None:
            rom_entry['reason'] = reason
        roms[family] = rom_entry

    root_type = _legacy_trust_root_type(spec)
    trust_roots = [
        {'type': root_type, 'value': value}
        for value in spec.verification.trusted_signers
    ]
    # A typed X.509 root would be inconsistent with a v1 sha256-only scheme.
    # Such legacy signer metadata was not enforceable, so retain safe loading by
    # dropping the ambiguous identity rather than claiming a trust mechanism.
    if not ({'ssh-signature', 'apk-signature'} & set(spec.verification.schemes)):
        trust_roots = []

    reasons = [reason.model_dump(mode='json') for reason in spec.reasons]
    if status == 'experimental' and not reasons:
        reasons.append(migration_reason)

    return {
        'schema_version': 2,
        'id': spec.id,
        'name': spec.name,
        'status': status,
        'adapter': spec.adapter,
        'lifecycle': _legacy_lifecycle(spec),
        'defaults': {
            'helper_enabled': spec.default_enabled,
            # v1's default was local to this helper and never asserted a Pixene
            # profile default.
            'pixene_profile_enabled': False,
        },
        'acknowledgement_required': False,
        'experimental_opt_in': None,
        'artifact_kinds': list(spec.artifact_kinds),
        'verification': {
            'schemes': list(spec.verification.schemes),
            'trust_roots': trust_roots,
            'digest_required': spec.verification.digest_required,
            'enforced_by': spec.verification.enforced_by,
        },
        'compatibility': {
            'roms': roms,
            'root_modes': list(spec.compatibility.root_modes),
            'architectures': list(spec.compatibility.architectures),
        },
        'capabilities': {
            'requires': {
                'root_provider': None,
                'zygisk_provider': None,
                'selective_signature_spoofing': False,
                'product_priv_app': False,
                'custom_init_selinux': False,
                'abis': list(spec.compatibility.architectures),
                'min_api': None,
                'max_api': None,
            },
            'provides': {
                'root': [],
                'zygisk': [],
                'selective_signature_spoofing': False,
                'product_priv_app': False,
                'custom_init_selinux': False,
            },
        },
        'legal': {
            'license': 'LicenseRef-Legacy-Unspecified',
            'source_url': None,
            'source_offer_required': False,
            'upstream_only_fetching': False,
            'local_only': True,
            'cache_policy': 'read-write',
            'allowed_output_scopes': ['local-unpublished'],
            'permission_record': None,
        },
        'dependencies': list(spec.dependencies),
        'conflicts': list(spec.conflicts),
        'warnings': [
            warning.model_dump(mode='json') for warning in spec.warnings
        ],
        'reasons': reasons,
    }


class ModuleCatalog:
    def __init__(self, modules: Sequence[ModuleSpec]) -> None:
        self.modules = tuple(modules)

    @property
    def supported(self) -> tuple[ModuleSpec, ...]:
        return tuple(module for module in self.modules if module.status == 'supported')

    def as_dict(self) -> dict[str, object]:
        return {
            'schema_version': 2,
            'modules': [
                module.model_dump(mode='json')
                for module in self.modules
            ],
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True) + '\n'

    def as_text(self) -> str:
        # Keep the existing text format: DEFAULT continues to mean the helper
        # default, while JSON exposes both distinct v2 defaults.
        lines = ['ID\tSTATUS\tDEFAULT\tARTIFACT KINDS']
        for module in self.modules:
            kinds = ','.join(module.artifact_kinds)
            enabled = 'yes' if module.default_enabled else 'no'
            lines.append(f'{module.id}\t{module.status}\t{enabled}\t{kinds}')
        return '\n'.join(lines) + '\n'


def load_catalog(
    directory: Path = MANIFESTS_DIR,
    registrations: Sequence[AdapterRegistration] = (
        INTERNAL_ADAPTERS + LOCKED_ADAPTERS
    ),
) -> ModuleCatalog:
    registration_by_id: dict[str, AdapterRegistration] = {}
    for registration in registrations:
        if not MODULE_ID_PATTERN.fullmatch(registration.id):
            raise CatalogError(
                f'Invalid internal adapter registration: {registration.id!r}'
            )
        if registration.id in registration_by_id:
            raise CatalogError(
                f'Duplicate internal adapter registration: {registration.id}'
            )
        registration_by_id[registration.id] = registration

    paths = sorted(directory.glob('*.toml'), key=lambda path: path.name)
    if not paths:
        raise CatalogError(f'No module manifests found in: {directory}')

    specs: list[ModuleSpec] = []
    seen_ids: set[str] = set()
    seen_adapters: set[str] = set()

    for path in paths:
        try:
            raw = tomlkit.loads(path.read_text(encoding='UTF-8')).unwrap()
            schema_version = raw.get('schema_version')
            if schema_version == 1:
                raw = migrate_v1_manifest(raw)
            elif schema_version != 2:
                raise ValueError(
                    f'unsupported schema_version: {schema_version!r}'
                )
            spec = ModuleSpec.model_validate(raw)
        except Exception as e:
            raise CatalogError(f'Invalid module manifest: {path}: {e}') from e

        if spec.id in seen_ids:
            raise CatalogError(f'Duplicate module ID: {spec.id}')
        if path.stem != spec.id:
            raise CatalogError(
                f'Manifest filename must match module ID: {path.name} != {spec.id}.toml'
            )
        if spec.adapter is not None:
            if spec.adapter not in registration_by_id:
                raise CatalogError(
                    f'Module {spec.id!r} uses unknown adapter: {spec.adapter!r}'
                )
            if spec.adapter in seen_adapters:
                raise CatalogError(
                    f'Duplicate module adapter registration: {spec.adapter}'
                )
            if spec.id != spec.adapter:
                raise CatalogError(
                    f'Legacy module ID must match its adapter: '
                    f'{spec.id!r} != {spec.adapter!r}'
                )

            registration = registration_by_id[spec.adapter]
            expectation = spec.verification
            if (
                set(expectation.schemes) != set(registration.verification_schemes)
                or set(expectation.trusted_signer_values) != set(registration.trusted_signers)
                or expectation.digest_required != registration.digest_required
            ):
                raise CatalogError(
                    f'Module {spec.id!r} verification expectation does not '
                    f'match its internal adapter'
                )

            seen_adapters.add(spec.adapter)

        seen_ids.add(spec.id)
        specs.append(spec)

    missing_adapters = set(registration_by_id) - seen_adapters
    if missing_adapters:
        raise CatalogError(
            'Missing supported module manifests for internal adapters: '
            f'{", ".join(sorted(missing_adapters))}'
        )

    for spec in specs:
        unknown = (set(spec.dependencies) | set(spec.conflicts)) - seen_ids
        if unknown:
            raise CatalogError(
                f'Module {spec.id!r} references unknown modules: '
                f'{", ".join(sorted(unknown))}'
            )

    # IDs, not filesystem or locale ordering, define the public registry order.
    specs.sort(key=lambda spec: spec.id)
    return ModuleCatalog(specs)


def main() -> None:
    parser = argparse.ArgumentParser(description='List image patch module metadata')
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
    args = parser.parse_args()

    catalog = load_catalog()
    if args.format == 'json':
        print(catalog.as_json(), end='')
    else:
        print(catalog.as_text(), end='')


if __name__ == '__main__':
    main()
