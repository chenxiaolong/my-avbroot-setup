# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

import patch as patch_script


class MultiOutputPatchTest(unittest.TestCase):
    def test_single_output_plan_is_unchanged(self) -> None:
        args = SimpleNamespace(
            output=Path('rootless.zip'),
            patch_arg=['--rootless'],
            secondary_output=None,
            secondary_patch_arg=[],
        )

        self.assertEqual(
            ((Path('rootless.zip'), ['--rootless']),),
            patch_script._patch_output_plans(args),
        )

    @mock.patch.object(patch_script.external, 'patch_ota')
    def test_secondary_output_reuses_prepared_replacements(
        self,
        patch_ota: mock.Mock,
    ) -> None:
        args = SimpleNamespace(
            input=Path('input.zip'),
            output=Path('rootless.zip'),
            patch_arg=['--rootless'],
            secondary_output=Path('magisk.zip'),
            secondary_patch_arg=[
                '--magisk',
                'Magisk.apk',
                '--magisk-preinit-device',
                'sda10',
            ],
            sign_cert_ota=Path('ota.crt'),
        )
        sign_key_avb = SimpleNamespace(key=Path('avb.key'))
        sign_key_ota = SimpleNamespace(key=Path('ota.key'))
        replacements = {
            'system': Path('prepared/system.img'),
            'vendor_boot': Path('prepared/vendor_boot.img'),
        }

        patch_script._patch_ota_outputs(
            args,
            sign_key_avb,
            sign_key_ota,
            replacements,
        )

        self.assertEqual(2, patch_ota.call_count)
        first, second = patch_ota.call_args_list
        self.assertEqual(Path('rootless.zip'), first.args[1])
        self.assertEqual(['--rootless'], first.args[6])
        self.assertEqual(Path('magisk.zip'), second.args[1])
        self.assertEqual(args.secondary_patch_arg, second.args[6])
        self.assertIs(replacements, first.args[5])
        self.assertIs(replacements, second.args[5])

    def test_secondary_output_requires_custota_skip(self) -> None:
        argv = [
            'patch.py',
            '--input', 'input.zip',
            '--output', 'rootless.zip',
            '--sign-key-avb', 'avb.key',
            '--sign-key-ota', 'ota.key',
            '--sign-cert-ota', 'ota.crt',
            '--secondary-output', 'magisk.zip',
            '--secondary-patch-arg=--magisk',
        ]

        with (
            mock.patch.object(sys, 'argv', argv),
            mock.patch.object(patch_script.modules, 'all_modules', return_value=[]),
            self.assertRaises(SystemExit),
        ):
            patch_script.parse_args()

    def test_secondary_output_cli_accepts_explicit_patch_plan(self) -> None:
        argv = [
            'patch.py',
            '--input', 'input.zip',
            '--output', 'rootless.zip',
            '--sign-key-avb', 'avb.key',
            '--sign-key-ota', 'ota.key',
            '--sign-cert-ota', 'ota.crt',
            '--patch-arg=--rootless',
            '--skip-custota-tool',
            '--secondary-output', 'magisk.zip',
            '--secondary-patch-arg=--magisk',
            '--secondary-patch-arg', 'Magisk.apk',
            '--secondary-patch-arg=--magisk-preinit-device',
            '--secondary-patch-arg', 'sda10',
        ]

        with (
            mock.patch.object(sys, 'argv', argv),
            mock.patch.object(patch_script.modules, 'all_modules', return_value=[]),
        ):
            args = patch_script.parse_args()

        self.assertEqual(Path('rootless.zip'), args.output)
        self.assertEqual(['--rootless'], args.patch_arg)
        self.assertEqual(Path('magisk.zip'), args.secondary_output)
        self.assertEqual(
            [
                '--magisk',
                'Magisk.apk',
                '--magisk-preinit-device',
                'sda10',
            ],
            args.secondary_patch_arg,
        )


if __name__ == '__main__':
    unittest.main()
