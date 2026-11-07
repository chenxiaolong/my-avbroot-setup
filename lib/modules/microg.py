# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Locked, non-executing microG image adapter for current LineageOS."""

from collections.abc import Iterable
import io
from pathlib import Path
import re
from typing import Final
import zipfile
import zlib

from lib.filesystem import CpioFs, ExtFs, ExtInstallRequest
from lib.modules import Module, ModuleRequirements
from lib.modules.registry import MICROG_APK_SIGNER_SHA256
from lib.modules.report import AdapterPatchResult
from lib.modules.verified import LockedAdapterContext, VerifiedArtifact


MODULE_ID: Final = 'microg'
RELEASE: Final = 'v0.3.17.252432'
GMSCORE_ARTIFACT_ID: Final = 'gmscore-apk'
COMPANION_ARTIFACT_ID: Final = 'companion-apk'
GMSCORE_VERSION_CODE: Final = 252432034
COMPANION_VERSION_CODE: Final = 84022634

GMSCORE_PATH: Final = '/product/priv-app/GmsCore/GmsCore.apk'
GMSCORE_LIB_PATH: Final = '/product/priv-app/GmsCore/lib'
COMPANION_PATH: Final = '/product/priv-app/FakeStore/FakeStore.apk'
GMSCORE_PRIVAPP_PATH: Final = (
    '/product/etc/permissions/privapp-permissions-com.google.android.gms.xml'
)
GMSCORE_DEFAULT_PERMISSIONS_PATH: Final = (
    '/product/etc/default-permissions/default-permissions-com.google.android.gms.xml'
)
GMSCORE_SYSCONFIG_PATH: Final = (
    '/product/etc/sysconfig/sysconfig-com.google.android.gms.xml'
)
COMPANION_PRIVAPP_PATH: Final = (
    '/product/etc/permissions/privapp-permissions-com.android.vending.xml'
)
COMPANION_DEFAULT_PERMISSIONS_PATH: Final = (
    '/product/etc/default-permissions/default-permissions-com.android.vending.xml'
)

INJECTED_PATHS: Final = tuple(sorted((
    GMSCORE_PATH,
    COMPANION_PATH,
    GMSCORE_PRIVAPP_PATH,
    GMSCORE_DEFAULT_PERMISSIONS_PATH,
    GMSCORE_SYSCONFIG_PATH,
    COMPANION_PRIVAPP_PATH,
    COMPANION_DEFAULT_PERMISSIONS_PATH,
)))

_EXPECTED_SIGNERS: Final = (
    ('apk-signer-sha256', MICROG_APK_SIGNER_SHA256),
)

# Android's nativeLibraryDir uses instruction-set names rather than the ABI
# directory names used inside APKs.
_ABI_LAYOUT: Final = {
    'arm64-v8a': ('arm64', 2, 183),  # ELFCLASS64, EM_AARCH64
    'armeabi-v7a': ('arm', 1, 40),  # ELFCLASS32, EM_ARM
    'x86_64': ('x86_64', 2, 62),  # ELFCLASS64, EM_X86_64
    'x86': ('x86', 1, 3),  # ELFCLASS32, EM_386
}
_NATIVE_LIBRARY_NAME: Final = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*\.so\Z')


def _product_image_path(mounted_path: str) -> str:
    """Map the runtime /product mount into product.img's filesystem root."""
    if not mounted_path.startswith('/product/'):
        raise MicroGAdapterError('invalid mounted product path')
    # AFSR unpacking exposes product.img contents at /, not /product.
    return mounted_path[len('/product'):]

GMSCORE_PRIVAPP_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="com.google.android.gms">
        <!-- Explicitly account for the diagnostic permission without granting
             access to system-service dumps. An omitted request aborts Android
             17 system_server when privileged permission enforcement is on. -->
        <deny-permission name="android.permission.DUMP"/>
        <permission name="android.permission.FAKE_PACKAGE_SIGNATURE"/>
        <permission name="android.permission.CHANGE_DEVICE_IDLE_TEMP_WHITELIST"/>
        <permission name="android.permission.FOREGROUND_SERVICE"/>
        <permission name="android.permission.INSTALL_LOCATION_PROVIDER"/>
        <permission name="android.permission.LOCATION_HARDWARE"/>
        <permission name="android.permission.MANAGE_USB"/>
        <permission name="android.permission.MODIFY_PHONE_STATE"/>
        <permission name="android.permission.NETWORK_SCAN"/>
        <permission name="android.permission.PROVIDE_REMOTE_CREDENTIALS"/>
        <permission name="android.permission.PROVIDE_DEFAULT_ENABLED_CREDENTIAL_SERVICE"/>
        <permission name="android.permission.READ_CONTACTS"/>
        <permission name="android.permission.START_ACTIVITIES_FROM_BACKGROUND"/>
        <permission name="android.permission.UPDATE_APP_OPS_STATS"/>
        <permission name="android.permission.UPDATE_DEVICE_STATS"/>
        <permission name="android.permission.WATCH_APPOPS"/>
        <permission name="android.permission.INTERACT_ACROSS_PROFILES"/>
        <permission name="android.permission.INTERACT_ACROSS_USERS"/>
    </privapp-permissions>
</permissions>
'''

GMSCORE_DEFAULT_PERMISSIONS_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<exceptions>
    <exception package="com.google.android.gms">
        <permission name="android.permission.BODY_SENSORS" fixed="false"/>
        <permission name="android.permission.GET_ACCOUNTS" fixed="false"/>
        <permission name="android.permission.READ_CONTACTS" fixed="false"/>
        <permission name="android.permission.WRITE_CONTACTS" fixed="false"/>
        <permission name="android.permission.ACCESS_COARSE_LOCATION" fixed="false"/>
        <permission name="android.permission.ACCESS_FINE_LOCATION" fixed="false"/>
        <permission name="android.permission.RECEIVE_SMS" fixed="false" whitelisted="true"/>
        <permission name="android.permission.READ_PHONE_STATE" fixed="false"/>
        <permission name="android.permission.READ_EXTERNAL_STORAGE" fixed="false"/>
        <permission name="android.permission.WRITE_EXTERNAL_STORAGE" fixed="false"/>
        <permission name="android.permission.CAMERA" fixed="false"/>
        <permission name="android.permission.POST_NOTIFICATIONS" fixed="false"/>
        <permission name="android.permission.SYSTEM_ALERT_WINDOW" fixed="false"/>
    </exception>
</exceptions>
'''

GMSCORE_SYSCONFIG_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<config>
    <allow-in-power-save package="com.google.android.gms"/>
    <allow-in-data-usage-save package="com.google.android.gms"/>
    <allow-unthrottled-location package="com.google.android.gms"/>
</config>
'''

COMPANION_PRIVAPP_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="com.android.vending">
        <permission name="android.permission.FAKE_PACKAGE_SIGNATURE"/>
        <permission name="android.permission.REQUEST_INSTALL_PACKAGES"/>
        <permission name="android.permission.DELETE_PACKAGES"/>
        <permission name="android.permission.INSTALL_PACKAGES"/>
        <permission name="android.permission.INTERACT_ACROSS_PROFILES"/>
        <permission name="android.permission.INTERACT_ACROSS_USERS"/>
    </privapp-permissions>
</permissions>
'''

COMPANION_DEFAULT_PERMISSIONS_XML: Final = b'''<?xml version="1.0" encoding="utf-8"?>
<exceptions>
    <exception package="com.android.vending">
        <permission name="android.permission.FAKE_PACKAGE_SIGNATURE" fixed="false"/>
        <permission name="android.permission.GET_ACCOUNTS" fixed="false"/>
        <permission name="android.permission.ACCESS_COARSE_LOCATION" fixed="false"/>
        <permission name="android.permission.POST_NOTIFICATIONS" fixed="false"/>
    </exception>
</exceptions>
'''


class MicroGAdapterError(ValueError):
    """The reviewed microG adapter contract was violated."""


def _read_artifact(artifact: VerifiedArtifact) -> bytes:
    with artifact.open() as source:
        data = source.read(artifact.size + 1)
    if len(data) != artifact.size:
        raise MicroGAdapterError(
            f'verified artifact changed size while reading: {artifact.id}'
        )
    return data


def _extract_native_libraries(apk: bytes) -> tuple[tuple[str, bytes], ...]:
    """Validate and extract APK JNI libraries without changing the signed APK."""
    libraries: list[tuple[str, bytes]] = []
    seen_names: set[str] = set()
    seen_destinations: set[str] = set()

    try:
        archive = zipfile.ZipFile(io.BytesIO(apk))
    except (OSError, zipfile.BadZipFile) as error:
        raise MicroGAdapterError('locked GmsCore APK is not a valid ZIP archive') from error

    with archive:
        for member in archive.infolist():
            name = member.orig_filename
            if (
                not name
                or member.filename != name
                or '\\' in name
                or '\0' in name
                or name.startswith('/')
                or '//' in name
                or any(part in ('.', '..') for part in name.rstrip('/').split('/'))
            ):
                raise MicroGAdapterError('GmsCore APK contains an unsafe ZIP path')
            if name in seen_names:
                raise MicroGAdapterError(
                    f'GmsCore APK contains a duplicate ZIP path: {name}'
                )
            seen_names.add(name)

            if not name.startswith('lib/'):
                continue
            parts = name.split('/')
            if len(parts) == 2 and parts == ['lib', '']:
                mode = member.external_attr >> 16
                if (mode & 0o170000) not in (0, 0o040000):
                    raise MicroGAdapterError(
                        'GmsCore APK contains a non-directory lib root'
                    )
                continue
            if len(parts) == 3 and parts[0] == 'lib' and parts[1] in _ABI_LAYOUT:
                if member.is_dir() and parts[2] == '':
                    mode = member.external_attr >> 16
                    if (mode & 0o170000) not in (0, 0o040000):
                        raise MicroGAdapterError(
                            f'GmsCore APK contains a non-directory ABI path: {name}'
                        )
                    continue
            if len(parts) != 3 or parts[0] != 'lib' or parts[1] not in _ABI_LAYOUT:
                raise MicroGAdapterError(
                    f'GmsCore APK contains an unexpected native-library path: {name}'
                )
            if member.is_dir() or not _NATIVE_LIBRARY_NAME.fullmatch(parts[2]):
                raise MicroGAdapterError(
                    f'GmsCore APK contains an unexpected native-library entry: {name}'
                )
            if member.flag_bits & 0x1:
                raise MicroGAdapterError(f'GmsCore native library is encrypted: {name}')

            abi = parts[1]
            instruction_set, expected_class, expected_machine = _ABI_LAYOUT[abi]
            destination = f'{instruction_set}/{parts[2]}'
            if destination in seen_destinations:
                raise MicroGAdapterError(
                    'GmsCore APK contains duplicate native-library output: '
                    f'{destination}'
                )
            seen_destinations.add(destination)

            mode = member.external_attr >> 16
            file_type = mode & 0o170000
            if file_type not in (0, 0o100000):
                raise MicroGAdapterError(
                    f'GmsCore native library is not a regular file: {name}'
                )
            try:
                data = archive.read(member)
            except (
                OSError,
                EOFError,
                RuntimeError,
                zipfile.BadZipFile,
                NotImplementedError,
                zlib.error,
            ) as error:
                raise MicroGAdapterError(
                    f'GmsCore native library failed ZIP integrity checks: {name}'
                ) from error
            if (
                len(data) < 20
                or data[:4] != b'\x7fELF'
                or data[4] != expected_class
                or data[5] not in (1, 2)
            ):
                raise MicroGAdapterError(
                    f'GmsCore native library has an invalid ELF header: {name}'
                )
            byte_order = 'little' if data[5] == 1 else 'big'
            if int.from_bytes(data[18:20], byte_order) != expected_machine:
                raise MicroGAdapterError(
                    f'GmsCore native library has the wrong ELF machine: {name}'
                )
            libraries.append((destination, data))

    if not libraries:
        raise MicroGAdapterError('locked GmsCore APK contains no supported native libraries')
    return tuple(sorted(libraries))


def _require_apk(
    artifact: VerifiedArtifact,
    *,
    artifact_id: str,
    package_name: str,
    version_code: int,
) -> None:
    if (
        artifact.id != artifact_id
        or artifact.kind != 'apk'
        or artifact.role != 'injection-input'
        or artifact.apk_package_name != package_name
        or artifact.apk_version_code != version_code
        or artifact.apk_signer_sha256 != MICROG_APK_SIGNER_SHA256
        or artifact.archive_members
    ):
        raise MicroGAdapterError(
            f'locked microG artifact has an unexpected identity or policy: '
            f'{artifact.id}'
        )


class MicroGModule(Module):
    """Install official microG Services and Companion as product priv-apps."""

    def __init__(self, context: LockedAdapterContext) -> None:
        if not isinstance(context, LockedAdapterContext):
            raise TypeError('microG adapter requires a LockedAdapterContext')
        if context.module_id != MODULE_ID or context.module_version != RELEASE:
            raise MicroGAdapterError('microG adapter received the wrong module version')
        if context.rom_family != 'lineageos':
            raise MicroGAdapterError('microG adapter supports only LineageOS')
        if context.decision.rom_status != 'experimental':
            raise MicroGAdapterError('LineageOS microG must remain experimental')
        if context.decision.module != MODULE_ID:
            raise MicroGAdapterError('microG compatibility decision is mismatched')
        if context.trusted_signers != _EXPECTED_SIGNERS:
            raise MicroGAdapterError('microG adapter trust root is not exact')

        by_id = {artifact.id: artifact for artifact in context.artifacts}
        if len(by_id) != len(context.artifacts) or set(by_id) != {
            COMPANION_ARTIFACT_ID,
            GMSCORE_ARTIFACT_ID,
        }:
            raise MicroGAdapterError(
                'microG lock must contain exactly Services and Companion APKs'
            )

        companion = by_id[COMPANION_ARTIFACT_ID]
        gmscore = by_id[GMSCORE_ARTIFACT_ID]
        _require_apk(
            companion,
            artifact_id=COMPANION_ARTIFACT_ID,
            package_name='com.android.vending',
            version_code=COMPANION_VERSION_CODE,
        )
        _require_apk(
            gmscore,
            artifact_id=GMSCORE_ARTIFACT_ID,
            package_name='com.google.android.gms',
            version_code=GMSCORE_VERSION_CODE,
        )
        self._companion_apk = _read_artifact(companion)
        self._gmscore_apk = _read_artifact(gmscore)
        self._native_libraries = _extract_native_libraries(self._gmscore_apk)

    def requirements(self) -> ModuleRequirements:
        return ModuleRequirements(set(), {'product'}, False)

    def inject(
        self,
        boot_fs: dict[str, CpioFs],
        ext_fs: dict[str, ExtFs],
        sepolicies: Iterable[Path],
        compatible_sepolicy: bool = False,
    ) -> AdapterPatchResult:
        del boot_fs, sepolicies, compatible_sepolicy
        if 'product' not in ext_fs:
            raise MicroGAdapterError('microG adapter requires the product filesystem')
        product = ext_fs['product']
        library_instruction_sets = tuple(sorted({
            destination.split('/', 1)[0]
            for destination, _ in self._native_libraries
        }))
        library_paths = tuple(
            f'{GMSCORE_LIB_PATH}/{destination}'
            for destination, _ in self._native_libraries
        )
        library_directories = (
            GMSCORE_LIB_PATH,
            *(
                f'{GMSCORE_LIB_PATH}/{instruction_set}'
                for instruction_set in library_instruction_sets
            ),
        )
        injected_paths = tuple(sorted((
            *INJECTED_PATHS,
            *library_directories,
            *library_paths,
        )))
        requests = [
            ExtInstallRequest(
                _product_image_path('/product/priv-app/GmsCore'), 'Directory', 0o755, 0, 0
            ),
            ExtInstallRequest(
                _product_image_path(GMSCORE_LIB_PATH), 'Directory', 0o755, 0, 0
            ),
            *(
                ExtInstallRequest(
                    _product_image_path(f'{GMSCORE_LIB_PATH}/{instruction_set}'),
                    'Directory', 0o755, 0, 0,
                )
                for instruction_set in library_instruction_sets
            ),
            ExtInstallRequest(
                _product_image_path(GMSCORE_PATH), 'RegularFile', 0o644, 0, 0, self._gmscore_apk
            ),
            *(
                ExtInstallRequest(
                    _product_image_path(f'{GMSCORE_LIB_PATH}/{destination}'),
                    'RegularFile', 0o755, 0, 0, data,
                )
                for destination, data in self._native_libraries
            ),
            ExtInstallRequest(
                _product_image_path('/product/priv-app/FakeStore'), 'Directory', 0o755, 0, 0
            ),
            ExtInstallRequest(
                _product_image_path(COMPANION_PATH), 'RegularFile', 0o644, 0, 0, self._companion_apk
            ),
            ExtInstallRequest(
                _product_image_path(GMSCORE_PRIVAPP_PATH),
                'RegularFile',
                0o644,
                0,
                0,
                GMSCORE_PRIVAPP_XML,
            ),
            ExtInstallRequest(
                _product_image_path(GMSCORE_DEFAULT_PERMISSIONS_PATH),
                'RegularFile',
                0o644,
                0,
                0,
                GMSCORE_DEFAULT_PERMISSIONS_XML,
            ),
            ExtInstallRequest(
                _product_image_path(GMSCORE_SYSCONFIG_PATH),
                'RegularFile',
                0o644,
                0,
                0,
                GMSCORE_SYSCONFIG_XML,
            ),
            ExtInstallRequest(
                _product_image_path(COMPANION_PRIVAPP_PATH),
                'RegularFile',
                0o644,
                0,
                0,
                COMPANION_PRIVAPP_XML,
            ),
            ExtInstallRequest(
                _product_image_path(COMPANION_DEFAULT_PERMISSIONS_PATH),
                'RegularFile',
                0o644,
                0,
                0,
                COMPANION_DEFAULT_PERMISSIONS_XML,
            ),
        ]
        # Check SELinux labels against Android's mounted /product paths while
        # writing to the product image root. Do not alter label semantics for
        # legacy system-image adapters or mutate shared context tables.
        results = product.install(requests, label_mountpoint='/product')
        # Keep patch-report paths in their mounted Android namespace, while
        # all ExtFs writes and metadata paths use product.img-relative paths.
        status_by_path = {
            '/product' + str(result.path): result.status
            for result in results
            if '/product' + str(result.path) in injected_paths
        }
        if set(status_by_path) != set(injected_paths):
            raise MicroGAdapterError(
                'filesystem installer returned incomplete microG results'
            )
        return AdapterPatchResult(
            injected_paths,
            tuple((path, status_by_path[path]) for path in injected_paths),
        )
