# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Static, data-only registry of trusted internal module adapters."""

import dataclasses
from importlib import import_module
import re
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lib.modules import LegacyCliModule, Module


MODULE_ID_PATTERN = re.compile(r'^[a-z][a-z0-9-]*$')

SSH_SIGNER_CHENXIAOLONG = \
    'ssh-ed25519-sha256:Ct0HoRyrFLrnF9W+A/BKEiJmwx7yWkgaW/JvghKrboA'
FDROID_REPOSITORY_CERT_SHA256 = \
    '43238D512C1E5EB2D6569F4A3AFBF5523418B82E0A3ED1552770ABB9A9C9CCAB'
FDROID_OPENPGP_PRIMARY = '37D2C98789D8311948394E3E41E7044E1DBA2E89'
FDROID_OPENPGP_SUBKEY = '802A9799016112346E1FEFF47A029E54DD5DCE7A'


@dataclasses.dataclass(frozen=True)
class AdapterRegistration:
    id: str
    constructor_module: str
    constructor_name: str
    verification_schemes: tuple[str, ...]
    trusted_signers: tuple[str, ...]
    digest_required: bool


def _chenxiaolong_adapter(
    id: str,
    constructor_name: str,
) -> AdapterRegistration:
    return AdapterRegistration(
        id=id,
        constructor_module=f'lib.modules.{id}',
        constructor_name=constructor_name,
        verification_schemes=('ssh-signature',),
        trusted_signers=(SSH_SIGNER_CHENXIAOLONG,),
        digest_required=False,
    )


# Order is public CLI compatibility. These identifiers are opaque and cannot
# name Python modules or objects.
INTERNAL_ADAPTERS = (
    _chenxiaolong_adapter('alterinstaller', 'AlterInstallerModule'),
    _chenxiaolong_adapter('bcr', 'BCRModule'),
    _chenxiaolong_adapter('custota', 'CustotaModule'),
    _chenxiaolong_adapter('msd', 'MSDModule'),
    _chenxiaolong_adapter('oemunlockonboot', 'OEMUnlockOnBootModule'),
)


def legacy_cli_module_types() -> tuple[type['LegacyCliModule'], ...]:
    """Resolve only the statically reviewed legacy CLI module classes."""
    from lib.modules import LegacyCliModule

    result: list[type[LegacyCliModule]] = []
    seen: set[str] = set()
    for registration in INTERNAL_ADAPTERS:
        if not MODULE_ID_PATTERN.fullmatch(registration.id):
            raise RuntimeError(f'Invalid internal module ID: {registration.id!r}')
        if registration.id in seen:
            raise RuntimeError(
                f'Duplicate internal module ID: {registration.id!r}'
            )
        seen.add(registration.id)

        adapter_module = import_module(registration.constructor_module)
        constructor = getattr(adapter_module, registration.constructor_name, None)
        if (
            not isinstance(constructor, type)
            or not issubclass(constructor, LegacyCliModule)
            or constructor.NAME != registration.id
        ):
            raise RuntimeError(
                f'Invalid legacy CLI module constructor: '
                f'{registration.constructor_module}.'
                f'{registration.constructor_name}'
            )
        result.append(constructor)

    return tuple(result)


# Locked adapters are deliberately separate from the legacy registry.  In
# particular, adding an adapter here must never add a legacy --module-* option
# or alter ``modules.all_modules()``.  Entries are reviewed source code, not
# names supplied by a catalog, profile, lock, or command line.
LOCKED_ADAPTERS: tuple[AdapterRegistration, ...] = (
    AdapterRegistration(
        id='fdroid-privileged-extension',
        constructor_module='lib.modules.fdroid_privileged_extension',
        constructor_name='FDroidPrivilegedExtensionModule',
        verification_schemes=(
            'sha256',
            'jar-signature',
            'openpgp-signature',
            'apk-signature',
        ),
        trusted_signers=(
            FDROID_REPOSITORY_CERT_SHA256,
            FDROID_OPENPGP_PRIMARY,
            FDROID_OPENPGP_SUBKEY,
        ),
        digest_required=True,
    ),
)


def locked_adapter_factories(
    registrations: Sequence[AdapterRegistration] = LOCKED_ADAPTERS,
) -> dict[str, Callable[[object], 'Module']]:
    """Load the trusted, static factories used by the locked patch boundary."""

    from lib.modules import Module

    result: dict[str, Callable[[object], Module]] = {}
    for registration in registrations:
        if (
            not MODULE_ID_PATTERN.fullmatch(registration.id)
            or registration.id in result
        ):
            raise RuntimeError(
                f'Invalid locked adapter registration: {registration.id!r}'
            )
        adapter_module = import_module(registration.constructor_module)
        constructor = getattr(
            adapter_module,
            registration.constructor_name,
            None,
        )
        # Validate the registry entry before invoking it.  Merely accepting a
        # callable would allow an accidentally registered function to execute
        # arbitrary work before ``construct_locked_adapters()`` can inspect its
        # return value.
        if not isinstance(constructor, type) or not issubclass(
            constructor,
            Module,
        ):
            raise RuntimeError(
                'Invalid locked module constructor: '
                f'{registration.constructor_module}.'
                f'{registration.constructor_name}'
            )
        result[registration.id] = constructor
    return result


def module_argument_dest(module_id: str) -> str:
    if not MODULE_ID_PATTERN.fullmatch(module_id):
        raise ValueError(f'Invalid module ID: {module_id!r}')
    dest_id = module_id.replace('-', '_')
    return f'module_{dest_id}'


def module_signature_argument_dest(module_id: str) -> str:
    return f'{module_argument_dest(module_id)}_sig'
