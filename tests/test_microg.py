# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

from io import BytesIO
from pathlib import Path, PurePosixPath
import re
import tempfile
import unittest
import warnings
import xml.etree.ElementTree as ET
from zipfile import ZIP_STORED, ZipFile

from lib.filesystem import ExtEntry, ExtFs, ExtInfo, ExtInstallResult
from lib.modules.locks import load_canonical_lock
from lib.modules.microg import (
    COMPANION_ARTIFACT_ID,
    COMPANION_PATH,
    COMPANION_VERSION_CODE,
    GMSCORE_ARTIFACT_ID,
    GMSCORE_PATH,
    GMSCORE_LIB_PATH,
    GMSCORE_VERSION_CODE,
    INJECTED_PATHS,
    MicroGAdapterError,
    MicroGModule,
    RELEASE,
    _extract_native_libraries,
)
from lib.modules.registry import MICROG_APK_SIGNER_SHA256
from lib.modules.resolver import CompatibilityDecision
from lib.modules.verified import LockedAdapterContext, VerifiedArtifact


class RecordingProduct:
    def __init__(self) -> None:
        self.requests = None

    def install(self, requests, *, label_mountpoint=''):
        if label_mountpoint != '/product':
            raise AssertionError('microG must use mounted product SELinux labels')
        self.requests = tuple(requests)
        return tuple(
            ExtInstallResult(Path(request.path), 'created')
            for request in self.requests
        )


def artifact(
    artifact_id: str,
    package_name: str,
    version_code: int,
    payload: bytes,
):
    source = tempfile.TemporaryFile()
    source.write(payload)
    source.flush()
    source.seek(0)
    return VerifiedArtifact(
        id=artifact_id,
        kind='apk',
        role='injection-input',
        version=str(version_code),
        size=len(payload),
        sha256='00' * 32,
        apk_package_name=package_name,
        apk_version_code=version_code,
        apk_signer_sha256=MICROG_APK_SIGNER_SHA256,
        archive_members=(),
        archive_apk_signers=(),
        license='Apache-2.0',
        source_offer_required=False,
        corresponding_source_artifact=None,
        allowed_output_scopes=(
            'local-unpublished',
            'private',
            'shared',
            'published',
        ),
        _source=source,
    )


_TEST_NATIVE_LIBRARIES = {
    'arm64-v8a': ('arm64', 2, 183),
    'armeabi-v7a': ('arm', 1, 40),
    'x86_64': ('x86_64', 2, 62),
    'x86': ('x86', 1, 3),
}


def synthetic_elf(elf_class: int, machine: int) -> bytes:
    """Return the smallest ELF header accepted by the adapter's validator."""
    header = bytearray(20)
    header[:4] = b'\x7fELF'
    header[4] = elf_class
    header[5] = 1
    header[6] = 1
    header[18:20] = machine.to_bytes(2, 'little')
    return bytes(header)


def synthetic_gmscore_apk(entries=None) -> bytes:
    if entries is None:
        entries = {
            f'lib/{abi}/libtest.so': synthetic_elf(elf_class, machine)
            for abi, (_, elf_class, machine) in _TEST_NATIVE_LIBRARIES.items()
        }
    buffer = BytesIO()
    with ZipFile(buffer, 'w', compression=ZIP_STORED) as archive:
        for name, payload in (entries.items() if hasattr(entries, 'items') else entries):
            archive.writestr(name, payload)
    return buffer.getvalue()


def synthetic_corrupt_crc_apk() -> bytes:
    member = 'lib/arm64-v8a/libtest.so'
    apk = bytearray(synthetic_gmscore_apk({
        member: synthetic_elf(2, 183),
    }))
    central = apk.find(b'PK\x01\x02')
    if central < 0 or apk[central + 46:central + 46 + len(member)] != member.encode():
        raise AssertionError('synthetic APK central directory is malformed')
    apk[central + 16] ^= 1  # Corrupt the central-directory CRC, not the payload.
    return bytes(apk)


def synthetic_encrypted_apk() -> bytes:
    member = 'lib/arm64-v8a/libtest.so'
    apk = bytearray(synthetic_gmscore_apk({
        member: synthetic_elf(2, 183),
    }))
    central = apk.find(b'PK\x01\x02')
    if central < 0 or apk[central + 46:central + 46 + len(member)] != member.encode():
        raise AssertionError('synthetic APK central directory is malformed')
    local = int.from_bytes(apk[central + 42:central + 46], 'little')
    apk[central + 8] |= 1  # General-purpose bit 0: encrypted member.
    apk[local + 6] |= 1
    return bytes(apk)


def context(rom_family='lineageos'):
    companion = artifact(
        COMPANION_ARTIFACT_ID,
        'com.android.vending',
        COMPANION_VERSION_CODE,
        b'companion',
    )
    gmscore = artifact(
        GMSCORE_ARTIFACT_ID,
        'com.google.android.gms',
        GMSCORE_VERSION_CODE,
        synthetic_gmscore_apk(),
    )
    ctx = LockedAdapterContext(
        module_id='microg',
        module_version=RELEASE,
        profile_id='lineage-pdx235',
        rom_family=rom_family,
        output_scope='published',
        lock_sha256='11' * 32,
        selection_fingerprint='22' * 32,
        decision=CompatibilityDecision(
            module='microg',
            rom_status='experimental',
            reason={'code': 'lineage-validation-pending', 'message': 'pending'},
            warnings=(),
        ),
        trusted_signers=(
            ('apk-signer-sha256', MICROG_APK_SIGNER_SHA256),
        ),
        artifacts=(companion, gmscore),
    )
    return ctx


def close_context(ctx):
    for item in ctx.artifacts:
        item._source.close()


class MicroGAdapterTest(unittest.TestCase):
    def test_installed_gmscore_policy_explicitly_denies_diagnostic_dump(self) -> None:
        # The pdx235 Android 17 boot crashed system_server because GmsCore's
        # DUMP request had neither a grant nor a denial in the product policy.
        # Account for that request without adding access to system-service dumps.
        ctx = context()
        self.addCleanup(close_context, ctx)
        product = RecordingProduct()
        MicroGModule(ctx).inject({}, {'product': product}, ())
        request = next(request for request in product.requests if str(request.path)
                       == '/etc/permissions/privapp-permissions-com.google.android.gms.xml')
        policy = ET.fromstring(request.data).find(
            "privapp-permissions[@package='com.google.android.gms']"
        )
        self.assertIsNotNone(policy)
        self.assertEqual(
            ['deny-permission'],
            [entry.tag for entry in policy
             if entry.get('name') == 'android.permission.DUMP'],
        )

    def test_injects_reviewed_product_privapp_layout(self) -> None:
        ctx = context()
        self.addCleanup(close_context, ctx)
        module = MicroGModule(ctx)
        product = RecordingProduct()
        report = module.inject({}, {'product': product}, ())
        by_path = {str(request.path): request for request in product.requests}
        expected_libraries = {
            f'{GMSCORE_LIB_PATH.removeprefix("/product")}/{instruction_set}/libtest.so':
                synthetic_elf(elf_class, machine)
            for _, (instruction_set, elf_class, machine) in _TEST_NATIVE_LIBRARIES.items()
        }
        expected_paths = {
            *INJECTED_PATHS,
            GMSCORE_LIB_PATH,
            *(f'{GMSCORE_LIB_PATH}/{instruction_set}'
              for instruction_set, _, _ in _TEST_NATIVE_LIBRARIES.values()),
            *(f'/product{path}' for path in expected_libraries),
        }
        self.assertEqual(expected_paths, set(report.injected_paths))
        self.assertEqual(synthetic_gmscore_apk(),
                         by_path[GMSCORE_PATH.removeprefix('/product')].data)
        self.assertEqual(b'companion', by_path[COMPANION_PATH.removeprefix('/product')].data)
        self.assertEqual(set(expected_libraries), {
            str(request.path) for request in product.requests
            if str(request.path).endswith('/libtest.so')
        })
        for path, payload in expected_libraries.items():
            request = by_path[path.removeprefix('/product')]
            self.assertEqual(payload, request.data)
            self.assertEqual(0o755, request.file_mode)
        self.assertNotIn('/product', {str(request.path) for request in product.requests})
        self.assertEqual({'product'}, module.requirements().ext_images)

    def test_rejects_unrecognised_or_invalid_native_libraries(self) -> None:
        invalid_apks = (
            (b'not a zip', 'not a valid ZIP archive'),
            (synthetic_gmscore_apk({'lib/unknown/libtest.so': b'ELF'}),
             'unexpected native-library path'),
            (synthetic_gmscore_apk({'lib/arm64-v8a/libtest.so': b'ELF'}),
             'invalid ELF header'),
            (synthetic_gmscore_apk({
                'lib/arm64-v8a/libtest.so': synthetic_elf(2, 40),
            }), 'wrong ELF machine'),
            (synthetic_gmscore_apk({'lib/arm64-v8a/../libtest.so': b'ELF'}),
             'unsafe ZIP path'),
            (synthetic_gmscore_apk({'classes.dex': b'dex'}),
             'contains no supported native libraries'),
            (synthetic_corrupt_crc_apk(),
             'failed ZIP integrity checks'),
            (synthetic_encrypted_apk(), 'native library is encrypted'),
        )
        for apk, message in invalid_apks:
            with self.subTest(message=message):
                with self.assertRaisesRegex(MicroGAdapterError, message):
                    _extract_native_libraries(apk)

        duplicate_name = 'lib/arm64-v8a/libtest.so'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            duplicate_apk = synthetic_gmscore_apk([
                (duplicate_name, synthetic_elf(2, 183)),
                (duplicate_name, synthetic_elf(2, 183)),
            ])
            with self.assertRaisesRegex(MicroGAdapterError, 'duplicate ZIP path'):
                _extract_native_libraries(duplicate_apk)


    def test_installs_into_real_product_image_root(self) -> None:
        # AFSR represents product.img at "/", NOT at "/product". This is
        # intentionally a real ExtFs installer, not a recording fake.
        context_data = context()
        self.addCleanup(close_context, context_data)
        module = MicroGModule(context_data)
        with tempfile.TemporaryDirectory() as tempdir:
            tree = Path(tempdir)
            parents = (
                '/',
                '/etc',
                '/etc/permissions',
                '/etc/default-permissions',
                '/etc/sysconfig',
                '/priv-app',
            )
            entries = []
            for path in parents:
                if path != '/':
                    (tree / path.lstrip('/')).mkdir(parents=True, exist_ok=True)
                entries.append(ExtEntry(
                    path=PurePosixPath(path),
                    file_type='Directory',
                    file_mode=0o755,
                    uid=0,
                    gid=0,
                    xattrs={'security.selinux': 'u:object_r:system_file:s0\0'},
                ))
            fs = ExtFs(
                info=ExtInfo(
                    metadata={
                        'features': [],
                        'block_size': 4096,
                        'reserved_percentage': 0,
                        'uuid': '00000000-0000-0000-0000-000000000000',
                    },
                    entries=entries,
                ),
                tree=tree,
                contexts=[
                    (
                        re.compile(r'/product/priv-app(?:/.*)?'),
                        'u:object_r:privapp_data_file:s0',
                    ),
                    (
                        re.compile(r'/product/.*'),
                        'u:object_r:system_file:s0',
                    ),
                ],
            )
            report = module.inject({}, {'product': fs}, ())
            self.assertEqual(
                synthetic_gmscore_apk(),
                (tree / GMSCORE_PATH.removeprefix('/product/')).read_bytes(),
            )
            self.assertEqual(
                synthetic_elf(2, 183),
                (tree / 'priv-app/GmsCore/lib/arm64/libtest.so').read_bytes(),
            )
            self.assertEqual(
                b'companion',
                (tree / COMPANION_PATH.removeprefix('/product/')).read_bytes(),
            )
            labels = {
                str(entry.path): entry.xattrs['security.selinux']
                for entry in fs.info.entries
            }
            self.assertEqual(
                'u:object_r:privapp_data_file:s0\0',
                labels['/priv-app/GmsCore/GmsCore.apk'],
            )
            self.assertEqual(
                'u:object_r:privapp_data_file:s0\0',
                labels['/priv-app/GmsCore/lib/arm64/libtest.so'],
            )
            self.assertEqual(
                'u:object_r:system_file:s0\0',
                labels['/etc/permissions/privapp-permissions-com.google.android.gms.xml'],
            )
            self.assertNotIn(PurePosixPath('/product'), {
                entry.path for entry in fs.info.entries
            })

    def test_checked_in_lock_matches_reviewed_release(self) -> None:
        lock, _ = load_canonical_lock(
            Path('locks/microg-v0.3.17.252432.json')
        )
        self.assertEqual(('microg',), tuple(module.id for module in lock.modules))
        module = lock.modules[0]
        self.assertEqual(RELEASE, module.version)
        by_id = {artifact.id: artifact for artifact in module.artifacts}
        self.assertEqual(
            {'companion-apk', 'gmscore-apk'},
            set(by_id),
        )
        expected = {
            'companion-apk': (
                'com.android.vending',
                COMPANION_VERSION_CODE,
                4210169,
                '9b8616011cc8f026bcbbe094df850794abb9d6d9f23214d7a8f8c4d1033ea012',
            ),
            'gmscore-apk': (
                'com.google.android.gms',
                GMSCORE_VERSION_CODE,
                108113833,
                'e5e6cba078bdec812b5450599350e5c1a12c8b7438da5bf77123af170f8c1a35',
            ),
        }
        for artifact_id, (package, version, size, digest) in expected.items():
            artifact = by_id[artifact_id]
            self.assertEqual(package, artifact.apk.package_name)
            self.assertEqual(version, artifact.apk.version_code)
            self.assertEqual(MICROG_APK_SIGNER_SHA256, artifact.apk.signer_sha256)
            self.assertEqual(size, artifact.size)
            self.assertEqual(digest, artifact.sha256)
            self.assertEqual(
                (
                    'https://github.com',
                    'https://release-assets.githubusercontent.com',
                ),
                artifact.allowed_origins,
            )

    def test_grapheneos_is_rejected_by_adapter(self) -> None:
        ctx = context('grapheneos')
        self.addCleanup(close_context, ctx)
        with self.assertRaisesRegex(MicroGAdapterError, 'only LineageOS'):
            MicroGModule(ctx)

    def test_wrong_signer_is_rejected(self) -> None:
        ctx = context()
        self.addCleanup(close_context, ctx)
        bad = ctx.artifacts[0]
        object.__setattr__(bad, 'apk_signer_sha256', 'ff' * 32)
        with self.assertRaisesRegex(MicroGAdapterError, 'unexpected identity'):
            MicroGModule(ctx)


if __name__ == '__main__':
    unittest.main()
