# SPDX-License-Identifier: GPL-3.0-only
"""Real catalog boundaries and authenticated OTA SDK binding for microG."""

from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from lib.modules.catalog import load_catalog
from lib.modules.locks import load_canonical_lock
from lib.modules.resolver import ResolutionError, ResolutionProfile, resolve_profile
import patch


ROOT = Path(__file__).resolve().parents[1]


def profile(api, *, family='lineageos', root_mode='rootless', scope='local-unpublished'):
    return ResolutionProfile.model_validate({
        'schema_version': 1,
        'id': 'microg-api-qualification',
        'rom_family': family,
        'root_mode': root_mode,
        'abi': 'arm64-v8a',
        'api_level': api,
        'output_scope': scope,
        'enabled_modules': ['microg'],
        'capabilities': {
            'root_providers': [],
            'zygisk_providers': [],
            'selective_signature_spoofing': True,
            'product_priv_app': True,
            'custom_init_selinux': False,
        },
    })


def selection(api):
    return SimpleNamespace(resolution=SimpleNamespace(
        selected_modules=('microg',), profile=profile(api)))


def ota(path, sdk):
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('META-INF/com/android/metadata',
                         f'post-sdk-level={sdk}\n'
                         'post-build=Sony/device/device:15/stock/build:user/release-keys\n')


def arguments(root, *, runtime=False, secondary=False):
    return SimpleNamespace(
        input=root / 'source.zip', output=root / 'rootless.zip',
        secondary_output=root / 'magisk.zip' if secondary else None,
        patch_arg=['--rootless', '--skip-system-ota-cert'],
        secondary_patch_arg=['--magisk', '--skip-system-ota-cert'] if secondary else [],
        sign_key_avb=root / 'avb.key', sign_key_ota=root / 'ota.key',
        sign_cert_ota=root / 'ota.crt', verify_public_key_avb=root / 'source.pk',
        verify_cert_ota=root / 'source.crt', pass_avb_env_var=None,
        pass_ota_env_var=None, pass_avb_file=None, pass_ota_file=None,
        compatible_sepolicy=False, skip_custota_tool=secondary,
        allow_source_care_map_mismatch=runtime, patch_report=root / 'report.json',
    )


class MicroGCompatibilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()
        cls.lock, cls.digest = load_canonical_lock(
            ROOT / 'locks' / 'microg-v0.3.17.252432.json')

    def test_api_36_and_37_resolve_as_experimental_with_real_catalog_and_lock(self):
        for api in (36, 37):
            for root_mode in ('rootless', 'rooted'):
                for scope in ('local-unpublished', 'published'):
                    with self.subTest(api=api, root_mode=root_mode, scope=scope):
                        result = resolve_profile(self.catalog,
                            profile(api, root_mode=root_mode, scope=scope),
                            self.lock, self.digest)
                        self.assertEqual(('microg',), result.selected_modules)
                        self.assertEqual('experimental', result.decisions[0].rom_status)

    def test_api_35_38_and_grapheneos_remain_rejected(self):
        for api, family, message in (
            (35, 'lineageos', 'requires API >= 36'),
            (38, 'lineageos', 'requires API <= 37'),
            (36, 'grapheneos', 'incompatible with grapheneos'),
            (37, 'grapheneos', 'incompatible with grapheneos'),
        ):
            with self.subTest(api=api, family=family), self.assertRaisesRegex(
                    ResolutionError, message):
                resolve_profile(self.catalog, profile(api, family=family),
                                self.lock, self.digest)


class MicroGOtaApiTest(unittest.TestCase):
    def test_metadata_sdk_is_used_instead_of_spoofed_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ota.zip'
            for api in (36, 37):
                ota(path, api)
                patch._require_microg_ota_api(path, selection(api))
                with self.assertRaisesRegex(ValueError, 'differs from authenticated OTA SDK'):
                    patch._require_microg_ota_api(path, selection(73 - api))
        # Other/no locked selections do not acquire a new metadata requirement.
        patch._require_microg_ota_api(Path('does-not-exist'), None)

    def test_missing_malformed_duplicate_and_oversized_metadata_fail_closed(self):
        invalid = (
            b'post-build=source\n',
            b'post-sdk-level=\n',
            b'post-sdk-level=37.0\n',
            b'post-sdk-level=037\n',
            'post-sdk-level=٣٧\n'.encode(),
            b'post-sdk-level=36\npost-sdk-level=37\n',
            b'post-sdk-level=37\npost-sdk-level=37\n',
            b'bad-line\n',
            b'=37\n',
            b'post-sdk-level=37\nextra=' + b'x' * (1024 * 1024),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ota.zip'
            for data in invalid:
                with self.subTest(data=data[:70]):
                    with zipfile.ZipFile(path, 'w') as archive:
                        archive.writestr('META-INF/com/android/metadata', data)
                    with self.assertRaises(ValueError):
                        patch._require_microg_ota_api(path, selection(37))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(path, 'w') as archive:
                    for _ in range(2):
                        archive.writestr('META-INF/com/android/metadata',
                                         b'post-sdk-level=37\n')
            with self.assertRaisesRegex(ValueError, 'one metadata entry'):
                patch._require_microg_ota_api(path, selection(37))
            with zipfile.ZipFile(path, 'w'):
                pass
            with self.assertRaisesRegex(ValueError, 'one metadata entry'):
                patch._require_microg_ota_api(path, selection(37))

    def test_mislabelled_source_is_rejected_after_authentication_before_unpack(self):
        for runtime in (False, True):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = arguments(root, runtime=runtime)
                ota(args.input, 37)
                events = []
                read_metadata = patch.get_ota_metadata
                def metadata(path):
                    events.append('metadata')
                    return read_metadata(path)
                def verify(*unused, **kwargs):
                    events.append('authenticate')
                    return {}
                with (
                    mock.patch.object(patch.modules, 'all_modules', return_value=[]),
                    mock.patch.object(patch.external, 'verify_ota', side_effect=verify),
                    mock.patch.object(patch.runtime_care_map, 'verify_output', side_effect=verify),
                    mock.patch.object(patch.runtime_care_map, 'read_map', return_value={}),
                    mock.patch.object(patch.runtime_care_map, 'write_map'),
                    mock.patch.object(patch, 'get_ota_metadata', side_effect=metadata),
                    mock.patch.object(patch.external, 'unpack_ota') as unpack,
                    mock.patch.object(patch.external, 'patch_ota') as signing,
                    mock.patch.object(patch, 'write_patch_report') as report,
                    self.assertRaisesRegex(ValueError, 'profile API 36 differs'),
                ):
                    patch._run(args, root, selection(36), ())
                self.assertEqual(['authenticate', 'metadata'], events)
                unpack.assert_not_called()
                signing.assert_not_called()
                report.assert_not_called()

    def test_failed_authentication_never_trusts_sdk_metadata(self):
        for runtime in (False, True):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = arguments(root, runtime=runtime)
                error = subprocess.CalledProcessError(1, ['verify'])
                with (
                    mock.patch.object(patch.modules, 'all_modules', return_value=[]),
                    mock.patch.object(patch.external, 'verify_ota', side_effect=error),
                    mock.patch.object(patch.runtime_care_map, 'verify_output', side_effect=error),
                    mock.patch.object(patch.runtime_care_map, 'read_map', return_value={}),
                    mock.patch.object(patch.runtime_care_map, 'write_map'),
                    mock.patch.object(patch, 'get_ota_metadata') as metadata,
                    self.assertRaises(subprocess.CalledProcessError),
                ):
                    patch._run(args, root, selection(37), ())
                metadata.assert_not_called()

    def test_wrong_primary_or_secondary_sdk_prevents_success_assets(self):
        for runtime in (False, True):
            for secondary in (False, True):
                with self.subTest(runtime=runtime, secondary=secondary), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    args = arguments(root, runtime=runtime, secondary=secondary)
                    ota(args.input, 37)
                    ota(args.output, 37 if secondary else 36)
                    if secondary:
                        ota(args.secondary_output, 36)
                    verified = []
                    def verify(ota_path, *unused, **kwargs):
                        verified.append(ota_path)
                        return {}
                    with (
                        mock.patch.object(patch.modules, 'all_modules', return_value=[]),
                        mock.patch.object(patch.external, 'verify_ota', side_effect=verify),
                        mock.patch.object(patch.runtime_care_map, 'verify_output', side_effect=verify),
                        mock.patch.object(patch.runtime_care_map, 'read_map', return_value={}),
                        mock.patch.object(patch.runtime_care_map, 'write_map'),
                        mock.patch.object(patch.runtime_care_map, 'expected_output_map',
                                          return_value=root / 'expected.pb'),
                        mock.patch.object(patch.external, 'patch_ota'),
                        mock.patch.object(patch.external, 'encode_output_avb_public_key'),
                        mock.patch.object(patch, 'build_patch_report', return_value=object()),
                        mock.patch.object(patch.external, 'generate_csig') as csig,
                        mock.patch.object(patch.external, 'generate_update_info') as metadata,
                        mock.patch.object(patch, 'write_patch_report') as report,
                        self.assertRaisesRegex(ValueError, 'profile API 37 differs'),
                    ):
                        patch._run(args, root, selection(37), ())
                    expected = [args.input, args.output]
                    if secondary:
                        expected.append(args.secondary_output)
                    self.assertEqual(expected, verified)
                    csig.assert_not_called()
                    metadata.assert_not_called()
                    report.assert_not_called()


if __name__ == '__main__':
    unittest.main()
