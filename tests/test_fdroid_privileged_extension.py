# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import dataclasses
import hashlib
from pathlib import Path, PurePosixPath
import re
from types import SimpleNamespace
import tempfile
from typing import BinaryIO
import unittest
from unittest import mock
import zipfile

from lib.filesystem import EntryExists, ExtEntry, ExtFs, ExtInfo
from lib.modules.catalog import load_catalog
from lib.modules.fdroid_privileged_extension import (
    CLIENT_ARTIFACT_ID,
    CLIENT_PATH,
    CLIENT_SOURCE_ARTIFACT_ID,
    CLIENT_VERSION_CODE,
    FDROID_SIGNER_SHA256,
    FPE_APK_MEMBER,
    FPE_PATH,
    FPE_SOURCE_ARTIFACT_ID,
    INJECTED_PATHS,
    OTA_ARTIFACT_ID,
    OTA_ALLOWLIST,
    PERMISSIONS_XML_MEMBER,
    PERMISSIONS_XML_PATH,
    FDroidAdapterError,
    FDroidPrivilegedExtensionModule,
)
from lib.modules.report import build_patch_report
from lib.modules.resolver import CompatibilityDecision
from lib.modules.verified import (
    LockedAdapterContext,
    VerifiedArchiveMember,
    VerifiedArtifact,
)


SYSTEM_LABEL = 'u:object_r:system_file:s0'
APP_LABEL = 'u:object_r:fdroid_app_file:s0'
PRIVAPP_LABEL = 'u:object_r:fdroid_privapp_file:s0'
PERMISSION_LABEL = 'u:object_r:permissions_file:s0'
XML = b'''<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="org.fdroid.fdroid.privileged">
        <permission name="android.permission.DELETE_PACKAGES"/>
        <permission name="android.permission.INSTALL_PACKAGES"/>
    </privapp-permissions>
</permissions>
'''


def directory(path: str, label: str = SYSTEM_LABEL) -> ExtEntry:
    return ExtEntry(
        path=PurePosixPath(path),
        file_type='Directory',
        file_mode=0o755,
        uid=0,
        gid=0,
        xattrs={'security.selinux': f'{label}\0'},
    )


class FDroidPrivilegedExtensionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.client = b'separately locked F-Droid client APK'
        self.fpe = b'locked F-Droid privileged extension APK'
        self.bundled_client = b'forbidden bundled client APK'
        self.source = b'matching GPL corresponding source'
        self.sentinel = self.root / 'installer-executed'
        self.handles: list[BinaryIO] = []
        self.filesystem_trees = 0
        self.addCleanup(self._close_handles)

    def _close_handles(self) -> None:
        for handle in self.handles:
            handle.close()

    def _source_handle(self, data: bytes):
        handle = tempfile.TemporaryFile()
        handle.write(data)
        handle.flush()
        handle.seek(0)
        self.handles.append(handle)
        return handle

    def _artifact(
        self,
        *,
        id: str,
        kind: str,
        role: str,
        data: bytes,
        license: str,
        package: str | None = None,
        version_code: int | None = None,
        signer: str | None = None,
        members: tuple[VerifiedArchiveMember, ...] = (),
        source_offer_required: bool = False,
        corresponding_source_artifact: str | None = None,
    ) -> VerifiedArtifact:
        return VerifiedArtifact(
            id=id,
            kind=kind,
            role=role,
            version='fixture',
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            apk_package_name=package,
            apk_version_code=version_code,
            apk_signer_sha256=signer,
            archive_members=members,
            archive_apk_signers=tuple(
                (member.name, member.apk_signer_sha256)
                for member in members
                if member.apk_signer_sha256 is not None
            ),
            license=license,
            source_offer_required=source_offer_required,
            corresponding_source_artifact=corresponding_source_artifact,
            allowed_output_scopes=(
                'local-unpublished', 'private', 'shared', 'published'
            ),
            _source=self._source_handle(data),
        )

    def _ota(self, xml: bytes = XML) -> tuple[bytes, tuple[VerifiedArchiveMember, ...]]:
        ota_path = self.root / f'fixture-{len(self.handles)}.zip'
        script = f'#!/bin/sh\ntouch {self.sentinel}\n'.encode()
        with zipfile.ZipFile(ota_path, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('META-INF/com/google/android/update-binary', script)
            archive.writestr('80-fdroid.sh', script)
            archive.writestr('F-Droid.apk', self.bundled_client)
            archive.writestr(FPE_APK_MEMBER, self.fpe)
            archive.writestr(PERMISSIONS_XML_MEMBER, xml)
        data = ota_path.read_bytes()
        members = tuple(sorted((
            VerifiedArchiveMember(
                name=FPE_APK_MEMBER,
                size=len(self.fpe),
                sha256=hashlib.sha256(self.fpe).hexdigest(),
                apk_package_name='org.fdroid.fdroid.privileged',
                apk_version_code=2130,
                apk_signer_sha256=FDROID_SIGNER_SHA256,
            ),
            VerifiedArchiveMember(
                name=PERMISSIONS_XML_MEMBER,
                size=len(xml),
                sha256=hashlib.sha256(xml).hexdigest(),
                apk_package_name=None,
                apk_version_code=None,
                apk_signer_sha256=None,
            ),
        ), key=lambda member: member.name))
        return data, members

    def context(self, xml: bytes = XML) -> LockedAdapterContext:
        ota, members = self._ota(xml)
        artifacts = (
            self._artifact(
                id=CLIENT_ARTIFACT_ID,
                kind='apk',
                role='injection-input',
                data=self.client,
                license='GPL-3.0-or-later',
                package='org.fdroid.fdroid',
                version_code=CLIENT_VERSION_CODE,
                signer=FDROID_SIGNER_SHA256,
                source_offer_required=True,
                corresponding_source_artifact=CLIENT_SOURCE_ARTIFACT_ID,
            ),
            self._artifact(
                id=CLIENT_SOURCE_ARTIFACT_ID,
                kind='other',
                role='corresponding-source',
                data=self.source,
                license='GPL-3.0-or-later',
            ),
            self._artifact(
                id=OTA_ARTIFACT_ID,
                kind='zip',
                role='injection-input',
                data=ota,
                license='Apache-2.0',
                members=members,
                corresponding_source_artifact=FPE_SOURCE_ARTIFACT_ID,
            ),
            self._artifact(
                id=FPE_SOURCE_ARTIFACT_ID,
                kind='other',
                role='corresponding-source',
                data=b'matching Apache FPE source',
                license='Apache-2.0',
            ),
        )
        return LockedAdapterContext(
            module_id='fdroid-privileged-extension',
            module_version='0.2.13+client-1.23.2',
            profile_id='lineage-fixture',
            rom_family='lineageos',
            output_scope='local-unpublished',
            lock_sha256='1' * 64,
            selection_fingerprint='2' * 64,
            decision=CompatibilityDecision(
                module='fdroid-privileged-extension',
                rom_status='experimental',
                reason={
                    'code': 'physical-validation-pending',
                    'message': 'Fixture remains experimental.',
                },
                warnings=(),
            ),
            trusted_signers=(
                ('apk-signer-sha256', FDROID_SIGNER_SHA256.upper()),
                ('openpgp-primary', '37D2C98789D8311948394E3E41E7044E1DBA2E89'),
                ('openpgp-subkey', '802A9799016112346E1FEFF47A029E54DD5DCE7A'),
                ('x509-cert-sha256', FDROID_SIGNER_SHA256.upper()),
            ),
            artifacts=artifacts,
        )

    def filesystem(self) -> ExtFs:
        tree = self.root / f'tree-{self.filesystem_trees}'
        self.filesystem_trees += 1
        for path in (
            'system/app',
            'system/priv-app',
            'system/etc/permissions',
        ):
            (tree / path).mkdir(parents=True, exist_ok=True)
        return ExtFs(
            info=ExtInfo(
                metadata={
                    "features": [],
                    "block_size": 4096,
                    "reserved_percentage": 0,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                },
                entries=[
                    directory('/'),
                    directory('/system'),
                    directory('/system/app'),
                    directory('/system/priv-app'),
                    directory('/system/etc'),
                    directory('/system/etc/permissions'),
                ],
            ),
            tree=tree,
            contexts=[
                (re.compile(r'/system/app/F-Droid(?:/.*)?'), APP_LABEL),
                (
                    re.compile(
                        r'/system/priv-app/F-DroidPrivilegedExtension(?:/.*)?'
                    ),
                    PRIVAPP_LABEL,
                ),
                (
                    re.compile(
                        r'/system/etc/permissions/'
                        r'permissions_org\.fdroid\.fdroid\.privileged\.xml'
                    ),
                    PERMISSION_LABEL,
                ),
                (re.compile(r'/.*'), SYSTEM_LABEL),
            ],
        )

    def test_manifest_is_default_off_locked_experimental_policy(self) -> None:
        module = next(
            module for module in load_catalog().modules
            if module.id == 'fdroid-privileged-extension'
        )
        self.assertEqual('experimental', module.status)
        self.assertEqual('static-image', module.lifecycle)
        self.assertFalse(module.defaults.helper_enabled)
        self.assertFalse(module.defaults.pixene_profile_enabled)
        self.assertTrue(module.experimental_opt_in.required)
        self.assertEqual(
            {'lineageos', 'grapheneos'}, set(module.compatibility.roms)
        )
        self.assertEqual(('rootless',), module.compatibility.root_modes)
        self.assertEqual('Apache-2.0 AND GPL-3.0-or-later', module.legal.license)
        self.assertTrue(module.legal.local_only)
        self.assertEqual(
            ('local-unpublished',), module.legal.allowed_output_scopes
        )
        self.assertIsNone(module.legal.permission_record)

    def test_injects_exact_three_files_with_explicit_metadata_and_labels(self) -> None:
        module = FDroidPrivilegedExtensionModule(self.context())
        fs = self.filesystem()

        result = module.inject({}, {'system': fs}, ())

        self.assertEqual(INJECTED_PATHS, result.injected_paths)
        self.assertEqual(
            tuple((path, 'created') for path in INJECTED_PATHS),
            result.path_statuses,
        )
        expected = {
            CLIENT_PATH: self.client,
            FPE_PATH: self.fpe,
            PERMISSIONS_XML_PATH: XML,
        }
        for path, data in expected.items():
            self.assertEqual(data, (fs.tree / path.removeprefix('/')).read_bytes())
        self.assertNotEqual(
            self.bundled_client,
            (fs.tree / CLIENT_PATH.removeprefix('/')).read_bytes(),
        )
        entries = {str(entry.path): entry for entry in fs.info.entries}
        expected_labels = {
            '/system/app/F-Droid': APP_LABEL,
            CLIENT_PATH: APP_LABEL,
            '/system/priv-app/F-DroidPrivilegedExtension': PRIVAPP_LABEL,
            FPE_PATH: PRIVAPP_LABEL,
            PERMISSIONS_XML_PATH: PERMISSION_LABEL,
        }
        for path, label in expected_labels.items():
            self.assertEqual(0, entries[path].uid)
            self.assertEqual(0, entries[path].gid)
            self.assertEqual(f'{label}\0', entries[path].xattrs['security.selinux'])
        self.assertEqual(0o755, entries['/system/app/F-Droid'].file_mode)
        self.assertEqual(0o755, entries['/system/priv-app/F-DroidPrivilegedExtension'].file_mode)
        for path in INJECTED_PATHS:
            self.assertEqual(0o644, entries[path].file_mode)
        self.assertFalse(self.sentinel.exists())

    def test_allows_unrelated_filesystems_and_only_mutates_system(self) -> None:
        module = FDroidPrivilegedExtensionModule(self.context())
        system = self.filesystem()
        vendor = self.filesystem()
        odm = self.filesystem()

        result = module.inject(
            {},
            {'system': system, 'vendor': vendor, 'odm': odm},
            (),
        )

        self.assertEqual(INJECTED_PATHS, result.injected_paths)
        for filesystem in (vendor, odm):
            self.assertFalse(
                (filesystem.tree / CLIENT_PATH.removeprefix('/')).exists()
            )
            self.assertFalse(
                (filesystem.tree / FPE_PATH.removeprefix('/')).exists()
            )

    def test_reinstall_is_identical_and_result_is_deterministic(self) -> None:
        module = FDroidPrivilegedExtensionModule(self.context())
        fs = self.filesystem()
        first = module.inject({}, {'system': fs}, ())
        second = module.inject({}, {'system': fs}, ())

        self.assertEqual(first.injected_paths, second.injected_paths)
        self.assertEqual(
            tuple((path, 'already-identical') for path in INJECTED_PATHS),
            second.path_statuses,
        )

    def test_metadata_collision_fails_before_partial_mutation(self) -> None:
        module = FDroidPrivilegedExtensionModule(self.context())
        fs = self.filesystem()
        module.inject({}, {'system': fs}, ())
        client_entry = next(
            entry for entry in fs.info.entries if str(entry.path) == CLIENT_PATH
        )
        client_entry.uid = 1
        before = [entry.model_copy(deep=True) for entry in fs.info.entries]

        with self.assertRaisesRegex(EntryExists, 'different content or metadata'):
            module.inject({}, {'system': fs}, ())

        self.assertEqual(before, fs.info.entries)
        self.assertEqual(self.fpe, (fs.tree / FPE_PATH.removeprefix('/')).read_bytes())

    def test_late_permission_collision_preflights_before_any_path_is_created(self) -> None:
        module = FDroidPrivilegedExtensionModule(self.context())
        fs = self.filesystem()
        with fs.open(PERMISSIONS_XML_PATH, 'wb') as output:
            output.write(b'different permission XML')
        before = [entry.model_copy(deep=True) for entry in fs.info.entries]

        with self.assertRaisesRegex(EntryExists, 'different content or metadata'):
            module.inject({}, {'system': fs}, ())

        self.assertEqual(before, fs.info.entries)
        self.assertFalse((fs.tree / CLIENT_PATH.removeprefix('/')).exists())
        self.assertFalse((fs.tree / FPE_PATH.removeprefix('/')).exists())
        self.assertFalse((fs.tree / 'system/app/F-Droid').exists())
        self.assertFalse(
            (fs.tree / 'system/priv-app/F-DroidPrivilegedExtension').exists()
        )

    def test_exact_artifact_ids_roles_and_ota_allowlist_are_required(self) -> None:
        context = self.context()
        with self.subTest('extra artifact'):
            extra = dataclasses.replace(
                context.artifacts[1], id='unexpected-source'
            )
            with self.assertRaisesRegex(FDroidAdapterError, 'exactly'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=context.artifacts + (extra,)
                ))
        with self.subTest('wrong role'):
            artifacts = list(context.artifacts)
            artifacts[0] = dataclasses.replace(
                artifacts[0], role='verification-evidence'
            )
            with self.assertRaisesRegex(FDroidAdapterError, 'kind or role'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=tuple(artifacts)
                ))
        with self.subTest('wrong client versionCode'):
            artifacts = list(context.artifacts)
            artifacts[0] = dataclasses.replace(
                artifacts[0], apk_version_code=CLIENT_VERSION_CODE - 1
            )
            with self.assertRaisesRegex(FDroidAdapterError, 'identity is not reviewed'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=tuple(artifacts)
                ))
        with self.subTest('missing FPE source'):
            with self.assertRaisesRegex(FDroidAdapterError, 'exactly'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=context.artifacts[:-1]
                ))
        with self.subTest('OTA source link is missing'):
            artifacts = list(context.artifacts)
            artifacts[2] = dataclasses.replace(
                artifacts[2], corresponding_source_artifact=None
            )
            with self.assertRaisesRegex(FDroidAdapterError, 'source obligation'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=tuple(artifacts)
                ))
        with self.subTest('FPE source has executable metadata'):
            artifacts = list(context.artifacts)
            artifacts[3] = dataclasses.replace(
                artifacts[3],
                apk_package_name='org.fdroid.fdroid.privileged',
            )
            with self.assertRaisesRegex(FDroidAdapterError, 'executable metadata'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=tuple(artifacts)
                ))
        with self.subTest('extra allowlisted member'):
            artifacts = list(context.artifacts)
            ota = artifacts[2]
            extra_member = VerifiedArchiveMember(
                name='update-binary',
                size=1,
                sha256='0' * 64,
                apk_package_name=None,
                apk_version_code=None,
                apk_signer_sha256=None,
            )
            artifacts[2] = dataclasses.replace(
                ota,
                archive_members=tuple(sorted(
                    ota.archive_members + (extra_member,),
                    key=lambda member: member.name,
                )),
            )
            with self.assertRaisesRegex(FDroidAdapterError, 'allowlist exactly'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=tuple(artifacts)
                ))
        with self.subTest('nested APK version is not exact'):
            artifacts = list(context.artifacts)
            ota = artifacts[2]
            members = list(ota.archive_members)
            apk_index = next(
                index for index, member in enumerate(members)
                if member.name == FPE_APK_MEMBER
            )
            members[apk_index] = dataclasses.replace(
                members[apk_index], apk_version_code=2129
            )
            artifacts[2] = dataclasses.replace(
                ota, archive_members=tuple(members)
            )
            with self.assertRaisesRegex(FDroidAdapterError, 'version 2130'):
                FDroidPrivilegedExtensionModule(dataclasses.replace(
                    context, artifacts=tuple(artifacts)
                ))

    def test_trusted_context_must_match_module_rom_status_and_roots(self) -> None:
        context = self.context()
        variants = {
            'module': dataclasses.replace(context, module_id='other-module'),
            'rom': dataclasses.replace(context, rom_family='unknown-rom'),
            'status': dataclasses.replace(
                context,
                decision=context.decision.model_copy(update={
                    'rom_status': 'supported',
                }),
            ),
            'roots': dataclasses.replace(
                context,
                trusted_signers=context.trusted_signers[:-1],
            ),
        }
        for name, variant in variants.items():
            with self.subTest(name=name), self.assertRaises(FDroidAdapterError):
                FDroidPrivilegedExtensionModule(variant)

    def test_xml_rejects_entities_extra_attributes_text_and_permissions(self) -> None:
        variants = {
            'dtd': XML.replace(
                b'<permissions>',
                b'<!DOCTYPE permissions [<!ENTITY x "bad">]><permissions>',
            ),
            'entity': XML.replace(b'<permissions>', b'<permissions>&amp;'),
            'attribute': XML.replace(b'<permissions>', b'<permissions extra="1">'),
            'text': XML.replace(b'<permissions>', b'<permissions>not-whitespace'),
            'permission': XML.replace(
                b'</privapp-permissions>',
                b'<permission name="android.permission.WRITE_SECURE_SETTINGS"/>'
                b'</privapp-permissions>',
            ),
        }
        for name, xml in variants.items():
            with self.subTest(name=name), self.assertRaises(FDroidAdapterError):
                FDroidPrivilegedExtensionModule(self.context(xml))

    def test_factory_rejects_raw_paths(self) -> None:
        with self.assertRaises(TypeError):
            FDroidPrivilegedExtensionModule(self.root)  # type: ignore[arg-type]

    def test_adapter_never_opens_installer_hooks_or_bundled_client(self) -> None:
        context = self.context()
        opened: list[str] = []
        original_open = zipfile.ZipFile.open

        def tracked_open(archive, name, *args, **kwargs):
            opened.append(name.filename if isinstance(name, zipfile.ZipInfo) else name)
            return original_open(archive, name, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, 'open', tracked_open):
            FDroidPrivilegedExtensionModule(context)

        self.assertEqual(list(OTA_ALLOWLIST), opened)
        self.assertNotIn('META-INF/com/google/android/update-binary', opened)
        self.assertNotIn('80-fdroid.sh', opened)
        self.assertNotIn('F-Droid.apk', opened)
        self.assertFalse(self.sentinel.exists())

    def test_report_contains_exact_statuses_signers_and_member_digests(self) -> None:
        context = self.context()
        module = FDroidPrivilegedExtensionModule(context)
        result = module.inject({}, {'system': self.filesystem()}, ())
        resolution = SimpleNamespace(
            profile=SimpleNamespace(
                id=context.profile_id,
                rom_family=context.rom_family,
                output_scope=context.output_scope,
            ),
            lock_sha256=context.lock_sha256,
            fingerprint=context.selection_fingerprint,
            selected_modules=(context.module_id,),
            decisions=(context.decision,),
        )
        selection = SimpleNamespace(resolution=resolution, contexts=(context,))

        first = build_patch_report(selection, ((context.module_id, result),))
        second = build_patch_report(selection, ((context.module_id, result),))

        self.assertEqual(first, second)
        self.assertEqual(
            ['created', 'created', 'created'],
            [item['status'] for item in first['injected_paths']],
        )
        ota_report = next(
            artifact for artifact in first['artifacts']
            if artifact['artifact'] == OTA_ARTIFACT_ID
        )
        self.assertEqual(
            {
                hashlib.sha256(self.fpe).hexdigest(),
                hashlib.sha256(XML).hexdigest(),
            },
            {member['sha256'] for member in ota_report['archive_members']},
        )
        self.assertIn(
            FDROID_SIGNER_SHA256,
            {signer['value'].lower() for signer in first['signers']},
        )
        artifact_by_id = {
            artifact['artifact']: artifact for artifact in first['artifacts']
        }
        self.assertTrue(
            artifact_by_id[CLIENT_ARTIFACT_ID]['source_offer_required']
        )
        self.assertEqual(
            CLIENT_SOURCE_ARTIFACT_ID,
            artifact_by_id[CLIENT_ARTIFACT_ID][
                'corresponding_source_artifact'
            ],
        )
        self.assertEqual(
            FPE_SOURCE_ARTIFACT_ID,
            artifact_by_id[OTA_ARTIFACT_ID]['corresponding_source_artifact'],
        )


if __name__ == '__main__':
    unittest.main()
