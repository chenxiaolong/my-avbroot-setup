# SPDX-License-Identifier: GPL-3.0-only
"""Postflight behavior at the authenticated tool boundary."""
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest import mock

from lib import external, runtime_care_map
import patch


class PostflightTest(unittest.TestCase):
    def test_secondary_failure_prevents_assets_in_both_modes(self):
        for runtime in (False, True):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                args = SimpleNamespace(
                    input=root/'source.zip', output=root/'rootless.zip',
                    secondary_output=root/'magisk.zip', patch_arg=['--rootless', '--skip-system-ota-cert'],
                    secondary_patch_arg=['--magisk', '--skip-system-ota-cert'], sign_key_avb=root/'avb.key',
                    sign_key_ota=root/'ota.key', sign_cert_ota=root/'ota.crt',
                    verify_public_key_avb=root/'source.pk', verify_cert_ota=root/'source.crt',
                    pass_avb_env_var=None, pass_ota_env_var=None, pass_avb_file=None,
                    pass_ota_file=None, compatible_sepolicy=False, skip_custota_tool=False,
                    allow_source_care_map_mismatch=runtime,
                )
                observed = []
                def verifier(ota, *unused, **kwargs):
                    observed.append(ota)
                    if ota == args.secondary_output:
                        raise subprocess.CalledProcessError(1, ['verify'])
                    return {}
                with (
                    mock.patch.object(patch.modules, 'all_modules', return_value=[]),
                    mock.patch.object(external, 'patch_ota'),
                    mock.patch.object(external, 'encode_output_avb_public_key'),
                    mock.patch.object(external, 'verify_ota', side_effect=verifier),
                    mock.patch.object(runtime_care_map, 'verify_output', side_effect=verifier),
                    mock.patch.object(runtime_care_map, 'read_map', return_value={}),
                    mock.patch.object(runtime_care_map, 'write_map'),
                    mock.patch.object(runtime_care_map, 'expected_output_map', return_value=root/'expected.pb'),
                    mock.patch.object(external, 'generate_csig') as csig,
                    mock.patch.object(external, 'generate_update_info') as metadata,
                    mock.patch.object(patch, 'write_patch_report') as report,
                    self.assertRaises(subprocess.CalledProcessError),
                ):
                    patch._run(args, root, None, ())
                self.assertEqual(observed, [args.input, args.output, args.secondary_output])
                csig.assert_not_called()
                metadata.assert_not_called()
                report.assert_not_called()

    def test_strict_expected_map_never_uses_error_waiver(self):
        with mock.patch.object(external, '_run_command') as run:
            external.verify_ota(Path('ota'), Path('key'), Path('cert'),
                                expected_care_map=Path('map'), verification_report=Path('report'))
        command = run.call_args.args[0]
        self.assertIn('--expected-care-map', command)
        self.assertIn('--verification-report', command)

    def test_key_encoding_uses_configured_signer(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'expected.pk'
            key = external.SigningKey(Path('sign.key'), 'AVB_PASS', None)
            with mock.patch.object(external, '_run_command',
                                   side_effect=lambda args: output.write_bytes(b'pk')) as run:
                external.encode_output_avb_public_key(key, output)
            command = run.call_args.args[0]
            self.assertEqual(command[command.index('--key')+1], key.key)
            self.assertEqual(command[command.index('--pass-env-var')+1], 'AVB_PASS')


class PayloadBindingTest(unittest.TestCase):
    def test_extracted_bytes_and_runtime_property_are_bound(self):
        import hashlib
        import json
        import zipfile
        for failure in ('hash', 'property', 'required-set', 'avb-flags', None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                ota = root/'ota.zip'
                expected = root/'expected.pb'
                entry = dict(name='odm', ranges='2,0,1', id='ro.odm.build.fingerprint', fingerprint='correct/value')
                runtime_care_map.write_map({'odm':entry}, expected)
                with zipfile.ZipFile(ota, 'w') as archive:
                    archive.writestr('care_map.pb', expected.read_bytes())
                image = b'protected-data'.ljust(4096, b'\0')
                def verified(*args, verification_report, **kwargs):
                    verification_report.write_text(json.dumps(dict(
                        schema='avbroot-ota-verification-v1', avb_headers=[dict(name='vbmeta', flags=3 if failure == 'avb-flags' else 0)],
                        required_care_map_partitions=[] if failure == 'required-set' else ['odm'],
                        partitions=[dict(name='odm', image_size=len(image),
                            image_sha256=hashlib.sha256(image).hexdigest(), verity_data_size=4096)])))
                def extract(unused, images, partitions):
                    images.mkdir()
                    (images/'odm.img').write_bytes(image if failure != 'hash' else b'wrong'.ljust(4096,b'\0'))
                with (
                    mock.patch.object(external, 'verify_ota', side_effect=verified),
                    mock.patch.object(external, 'unpack_ota', side_effect=extract),
                    mock.patch.object(runtime_care_map, 'filesystem_fingerprint',
                        return_value='wrong/value' if failure == 'property' else 'correct/value') as props,
                ):
                    if failure is None:
                        runtime_care_map.verify_output(ota, expected, root/'key', root/'cert', root/'proof')
                    else:
                        with self.assertRaises(ValueError):
                            runtime_care_map.verify_output(ota, expected, root/'key', root/'cert', root/'proof')
                    if failure in ('hash','required-set','avb-flags'):
                        props.assert_not_called()


class PropertyScratchTest(unittest.TestCase):
    def test_reader_releases_trees_on_success_and_failure(self):
        for valid in (False, True):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                scratch = root/'property'
                image = root/'image'
                raw = bytearray(4096)
                raw[1080:1082] = b'\x53\xef'
                image.write_bytes(raw)
                def unpack_fs(image, directory):
                    props = directory/'fs_tree'/'etc'
                    props.mkdir(parents=True)
                    (props/'build.prop').write_text(
                        'ro.odm.build.fingerprint=actual/value\n' if valid else '# missing\n')
                with (
                    mock.patch.object(external, 'unpack_fs', side_effect=unpack_fs),
                ):
                    if valid:
                        self.assertEqual('actual/value', runtime_care_map.filesystem_fingerprint(
                            root/'image', 'odm', scratch))
                    else:
                        with self.assertRaises(ValueError):
                            runtime_care_map.filesystem_fingerprint(root/'image', 'odm', scratch)
                self.assertFalse(scratch.exists())
