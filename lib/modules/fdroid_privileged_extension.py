# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Reviewed, non-executing F-Droid Privileged Extension image adapter."""

from collections.abc import Iterable
import hashlib
from pathlib import Path
from typing import Final
import xml.etree.ElementTree as ET
import zipfile

from lib.filesystem import CpioFs, ExtFs, ExtInstallRequest
from lib.modules import Module, ModuleRequirements
from lib.modules.registry import (
    FDROID_OPENPGP_PRIMARY,
    FDROID_OPENPGP_SUBKEY,
    FDROID_REPOSITORY_CERT_SHA256,
)
from lib.modules.report import AdapterPatchResult
from lib.modules.verified import (
    LockedAdapterContext,
    VerifiedArchiveMember,
    VerifiedArtifact,
)


MODULE_ID: Final = 'fdroid-privileged-extension'
FDROID_SIGNER_SHA256: Final = FDROID_REPOSITORY_CERT_SHA256.lower()

CLIENT_ARTIFACT_ID: Final = 'fdroid-client-apk'
CLIENT_SOURCE_ARTIFACT_ID: Final = 'fdroid-client-source'
OTA_ARTIFACT_ID: Final = 'fdroid-privileged-extension-ota'
FPE_SOURCE_ARTIFACT_ID: Final = 'fdroid-privileged-extension-source'

CLIENT_VERSION_CODE: Final = 1023052
FPE_VERSION_CODE: Final = 2130

FPE_APK_MEMBER: Final = 'F-DroidPrivilegedExtension.apk'
PERMISSIONS_XML_MEMBER: Final = (
    'permissions_org.fdroid.fdroid.privileged.xml'
)
OTA_ALLOWLIST: Final = (FPE_APK_MEMBER, PERMISSIONS_XML_MEMBER)
OTA_MAX_MEMBER_SIZE: Final = 16 * 1024 * 1024
OTA_MAX_STREAMED_BYTES: Final = 32 * 1024 * 1024

CLIENT_PATH: Final = '/system/app/F-Droid/F-Droid.apk'
FPE_PATH: Final = (
    '/system/priv-app/F-DroidPrivilegedExtension/'
    'F-DroidPrivilegedExtension.apk'
)
PERMISSIONS_XML_PATH: Final = (
    '/system/etc/permissions/permissions_org.fdroid.fdroid.privileged.xml'
)
INJECTED_PATHS: Final = tuple(sorted((CLIENT_PATH, FPE_PATH, PERMISSIONS_XML_PATH)))

_EXPECTED_PERMISSIONS: Final = frozenset({
    'android.permission.DELETE_PACKAGES',
    'android.permission.INSTALL_PACKAGES',
})
_EXPECTED_TRUSTED_SIGNERS: Final = (
    ('apk-signer-sha256', FDROID_REPOSITORY_CERT_SHA256),
    ('openpgp-primary', FDROID_OPENPGP_PRIMARY),
    ('openpgp-subkey', FDROID_OPENPGP_SUBKEY),
    ('x509-cert-sha256', FDROID_REPOSITORY_CERT_SHA256),
)


class FDroidAdapterError(ValueError):
    """The reviewed adapter contract or payload layout was violated."""


def _require_artifact(
    artifact: VerifiedArtifact,
    *,
    kind: str,
    role: str,
    license: str,
    source_offer_required: bool,
    corresponding_source_artifact: str | None,
) -> None:
    if artifact.kind != kind or artifact.role != role:
        raise FDroidAdapterError(
            f'locked artifact has an unexpected kind or role: {artifact.id}'
        )
    if artifact.license != license:
        raise FDroidAdapterError(
            f'locked artifact has an unexpected license policy: {artifact.id}'
        )
    if (
        artifact.source_offer_required != source_offer_required
        or artifact.corresponding_source_artifact
        != corresponding_source_artifact
    ):
        raise FDroidAdapterError(
            f'locked artifact has an unexpected source obligation: {artifact.id}'
        )


def _read_artifact(artifact: VerifiedArtifact) -> bytes:
    with artifact.open() as source:
        data = source.read(artifact.size + 1)
    if len(data) != artifact.size:
        raise FDroidAdapterError(
            f'verified artifact changed size while reading: {artifact.id}'
        )
    if hashlib.sha256(data).hexdigest() != artifact.sha256:
        raise FDroidAdapterError(
            f'verified artifact changed digest while reading: {artifact.id}'
        )
    return data


def _read_ota_members(artifact: VerifiedArtifact) -> dict[str, bytes]:
    """Boundedly read only the two reviewed members from the pinned inode.

    ``open_verified_selection()`` has already applied the complete hostile-ZIP
    inspection policy to this same inode. This stage deliberately does not open
    any other member, including installer hooks and the bundled client.
    """

    expected_by_name = {
        member.name: member for member in artifact.archive_members
    }
    result: dict[str, bytes] = {}
    total = 0
    try:
        with artifact.open() as source, zipfile.ZipFile(source, 'r') as archive:
            infos = archive.infolist()
            for name in OTA_ALLOWLIST:
                matches = [info for info in infos if info.filename == name]
                if len(matches) != 1 or matches[0].is_dir():
                    raise FDroidAdapterError(
                        f'FPE OTA member is missing or duplicated: {name}'
                    )
                info = matches[0]
                expected = expected_by_name[name]
                if (
                    info.file_size != expected.size
                    or info.file_size > OTA_MAX_MEMBER_SIZE
                ):
                    raise FDroidAdapterError(
                        f'FPE OTA member has an unexpected size: {name}'
                    )
                chunks: list[bytes] = []
                streamed = 0
                with archive.open(info, 'r') as member_source:
                    while chunk := member_source.read(64 * 1024):
                        streamed += len(chunk)
                        total += len(chunk)
                        if (
                            streamed > expected.size
                            or total > OTA_MAX_STREAMED_BYTES
                        ):
                            raise FDroidAdapterError(
                                f'FPE OTA member exceeded its byte limit: {name}'
                            )
                        chunks.append(chunk)
                data = b''.join(chunks)
                if (
                    len(data) != expected.size
                    or hashlib.sha256(data).hexdigest() != expected.sha256
                ):
                    raise FDroidAdapterError(
                        f'verified OTA member changed while reading: {name}'
                    )
                result[name] = data
    except FDroidAdapterError:
        raise
    except (EOFError, OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise FDroidAdapterError('FPE OTA failed bounded member reading') from error
    return result


def _require_no_content(value: str | None, where: str) -> None:
    if value is not None and value.strip():
        raise FDroidAdapterError(f'permission XML contains unexpected text: {where}')


def _validate_permissions_xml(data: bytes) -> None:
    # ElementTree does not retrieve external entities, but rejecting all entity,
    # DTD, comment, and processing-instruction syntax keeps this tiny format
    # independent of parser behavior and prevents semantic aliases.
    if data.startswith(b'\xef\xbb\xbf'):
        raise FDroidAdapterError('permission XML must not contain a byte-order mark')
    try:
        data.decode('UTF-8')
    except UnicodeDecodeError as error:
        raise FDroidAdapterError('permission XML is not UTF-8') from error
    if b'<!' in data or b'&' in data:
        raise FDroidAdapterError('permission XML cannot contain DTDs or entities')
    declaration = b'<?xml version="1.0" encoding="utf-8"?>'
    if not data.startswith(declaration):
        raise FDroidAdapterError('permission XML has an unexpected declaration')
    if b'<?' in data[len(declaration):]:
        raise FDroidAdapterError(
            'permission XML cannot contain processing instructions'
        )
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise FDroidAdapterError('permission XML is malformed') from error

    if root.tag != 'permissions' or root.attrib:
        raise FDroidAdapterError('permission XML root must be plain permissions')
    _require_no_content(root.text, 'permissions')
    _require_no_content(root.tail, 'after permissions')
    children = list(root)
    if len(children) != 1:
        raise FDroidAdapterError(
            'permission XML must contain one privapp-permissions block'
        )

    privapp = children[0]
    if privapp.tag != 'privapp-permissions' or privapp.attrib != {
        'package': 'org.fdroid.fdroid.privileged',
    }:
        raise FDroidAdapterError(
            'permission XML targets an unexpected privileged package'
        )
    _require_no_content(privapp.text, 'privapp-permissions')
    _require_no_content(privapp.tail, 'after privapp-permissions')

    permissions: list[str] = []
    for permission in privapp:
        if permission.tag != 'permission' or set(permission.attrib) != {'name'}:
            raise FDroidAdapterError(
                'permission XML contains an unexpected element or attribute'
            )
        _require_no_content(permission.text, 'permission')
        _require_no_content(permission.tail, 'after permission')
        if list(permission):
            raise FDroidAdapterError('permission XML nests elements in permission')
        permissions.append(permission.attrib['name'])
    if len(permissions) != 2 or frozenset(permissions) != _EXPECTED_PERMISSIONS:
        raise FDroidAdapterError(
            'permission XML grants permissions outside the reviewed allowlist'
        )


def _validate_fpe_members(
    members: tuple[VerifiedArchiveMember, ...],
) -> None:
    if tuple(member.name for member in members) != tuple(sorted(OTA_ALLOWLIST)):
        raise FDroidAdapterError(
            'FPE OTA lock must allowlist exactly the reviewed APK and XML'
        )
    by_name = {member.name: member for member in members}
    fpe_apk = by_name[FPE_APK_MEMBER]
    if (
        fpe_apk.apk_package_name != 'org.fdroid.fdroid.privileged'
        or fpe_apk.apk_version_code != FPE_VERSION_CODE
        or fpe_apk.apk_signer_sha256 != FDROID_SIGNER_SHA256
    ):
        raise FDroidAdapterError('FPE APK lock identity is not reviewed version 2130')
    xml = by_name[PERMISSIONS_XML_MEMBER]
    if any((
        xml.apk_package_name is not None,
        xml.apk_version_code is not None,
        xml.apk_signer_sha256 is not None,
    )):
        raise FDroidAdapterError('permission XML cannot have APK identity metadata')


class FDroidPrivilegedExtensionModule(Module):
    """Install only the separately locked client and two reviewed OTA members."""

    def __init__(self, context: LockedAdapterContext) -> None:
        if not isinstance(context, LockedAdapterContext):
            raise TypeError('F-Droid adapter requires a LockedAdapterContext')
        if context.module_id != MODULE_ID:
            raise FDroidAdapterError('F-Droid adapter received the wrong module')
        if context.rom_family not in ('lineageos', 'grapheneos'):
            raise FDroidAdapterError('F-Droid adapter received an unreviewed ROM family')
        if context.decision.rom_status != 'experimental':
            raise FDroidAdapterError('F-Droid adapter must remain experimental')
        if context.decision.module != MODULE_ID:
            raise FDroidAdapterError('F-Droid compatibility decision is mismatched')
        if context.trusted_signers != _EXPECTED_TRUSTED_SIGNERS:
            raise FDroidAdapterError('F-Droid adapter trust roots are not exact')

        by_id = {artifact.id: artifact for artifact in context.artifacts}
        expected_ids = {
            CLIENT_ARTIFACT_ID,
            CLIENT_SOURCE_ARTIFACT_ID,
            OTA_ARTIFACT_ID,
            FPE_SOURCE_ARTIFACT_ID,
        }
        if len(by_id) != len(context.artifacts) or set(by_id) != expected_ids:
            raise FDroidAdapterError(
                'F-Droid lock must contain exactly the reviewed artifact roles'
            )

        client = by_id[CLIENT_ARTIFACT_ID]
        _require_artifact(
            client,
            kind='apk',
            role='injection-input',
            license='GPL-3.0-or-later',
            source_offer_required=True,
            corresponding_source_artifact=CLIENT_SOURCE_ARTIFACT_ID,
        )
        if (
            client.apk_package_name != 'org.fdroid.fdroid'
            or client.apk_version_code != CLIENT_VERSION_CODE
            or client.apk_signer_sha256 != FDROID_SIGNER_SHA256
            or client.archive_members
        ):
            raise FDroidAdapterError('F-Droid client APK identity is not reviewed')

        client_source = by_id[CLIENT_SOURCE_ARTIFACT_ID]
        _require_artifact(
            client_source,
            kind='other',
            role='corresponding-source',
            license='GPL-3.0-or-later',
            source_offer_required=False,
            corresponding_source_artifact=None,
        )
        if (
            client_source.apk_package_name is not None
            or client_source.apk_version_code is not None
            or client_source.apk_signer_sha256 is not None
            or client_source.archive_members
        ):
            raise FDroidAdapterError('F-Droid source artifact has executable metadata')

        fpe_source = by_id[FPE_SOURCE_ARTIFACT_ID]
        _require_artifact(
            fpe_source,
            kind='other',
            role='corresponding-source',
            license='Apache-2.0',
            source_offer_required=False,
            corresponding_source_artifact=None,
        )
        if (
            fpe_source.apk_package_name is not None
            or fpe_source.apk_version_code is not None
            or fpe_source.apk_signer_sha256 is not None
            or fpe_source.archive_members
        ):
            raise FDroidAdapterError('FPE source artifact has executable metadata')

        ota = by_id[OTA_ARTIFACT_ID]
        _require_artifact(
            ota,
            kind='zip',
            role='injection-input',
            license='Apache-2.0',
            source_offer_required=False,
            corresponding_source_artifact=FPE_SOURCE_ARTIFACT_ID,
        )
        if any((
            ota.apk_package_name is not None,
            ota.apk_version_code is not None,
            ota.apk_signer_sha256 is not None,
        )):
            raise FDroidAdapterError('FPE OTA cannot have top-level APK metadata')
        _validate_fpe_members(ota.archive_members)

        # Read only verified open-inode capabilities. No installer hook, bundled
        # client, cache path, URL, or raw lock path is accepted by this adapter.
        self._client_apk = _read_artifact(client)
        ota_members = _read_ota_members(ota)
        self._fpe_apk = ota_members[FPE_APK_MEMBER]
        self._permissions_xml = ota_members[PERMISSIONS_XML_MEMBER]
        _validate_permissions_xml(self._permissions_xml)

    def requirements(self) -> ModuleRequirements:
        return ModuleRequirements(set(), {'system'}, False)

    def inject(
        self,
        boot_fs: dict[str, CpioFs],
        ext_fs: dict[str, ExtFs],
        sepolicies: Iterable[Path],
        compatible_sepolicy: bool = False,
    ) -> AdapterPatchResult:
        del boot_fs, sepolicies, compatible_sepolicy
        if 'system' not in ext_fs:
            raise FDroidAdapterError('F-Droid adapter requires the system filesystem')
        system = ext_fs['system']
        requests = (
            ExtInstallRequest(
                '/system/app/F-Droid', 'Directory', 0o755, 0, 0
            ),
            ExtInstallRequest(CLIENT_PATH, 'RegularFile', 0o644, 0, 0, self._client_apk),
            ExtInstallRequest(
                '/system/priv-app/F-DroidPrivilegedExtension',
                'Directory',
                0o755,
                0,
                0,
            ),
            ExtInstallRequest(FPE_PATH, 'RegularFile', 0o644, 0, 0, self._fpe_apk),
            ExtInstallRequest(
                PERMISSIONS_XML_PATH,
                'RegularFile',
                0o644,
                0,
                0,
                self._permissions_xml,
            ),
        )
        results = system.install(requests)
        status_by_path = {
            str(result.path): result.status
            for result in results
            if str(result.path) in INJECTED_PATHS
        }
        if set(status_by_path) != set(INJECTED_PATHS):
            raise FDroidAdapterError('filesystem installer returned incomplete results')
        return AdapterPatchResult(
            INJECTED_PATHS,
            tuple((path, status_by_path[path]) for path in INJECTED_PATHS),
        )
