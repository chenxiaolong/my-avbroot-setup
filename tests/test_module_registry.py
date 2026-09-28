# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import argparse
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from lib import modules
from lib.modules.alterinstaller import AlterInstallerModule
from lib.modules.bcr import BCRModule
from lib.modules.custota import CustotaModule
from lib.modules.fdroid_privileged_extension import (
    FDroidPrivilegedExtensionModule,
)
from lib.modules.msd import MSDModule
from lib.modules.oemunlockonboot import OEMUnlockOnBootModule
from lib.modules.registry import (
    AdapterRegistration,
    LOCKED_ADAPTERS,
    locked_adapter_factories,
    module_argument_dest,
)
import patch as patch_script


EXPECTED_MODULES = [
    'alterinstaller',
    'bcr',
    'custota',
    'msd',
    'oemunlockonboot',
]
EXPECTED_CONSTRUCTORS = [
    AlterInstallerModule,
    BCRModule,
    CustotaModule,
    MSDModule,
    OEMUnlockOnBootModule,
]


class ModuleRegistryTest(unittest.TestCase):
    def tearDown(self) -> None:
        modules.all_modules.cache_clear()

    def test_locked_registry_is_separate_from_legacy_modules(self) -> None:
        self.assertEqual(
            ['fdroid-privileged-extension'],
            [registration.id for registration in LOCKED_ADAPTERS],
        )
        self.assertEqual(
            {'fdroid-privileged-extension': FDroidPrivilegedExtensionModule},
            locked_adapter_factories(),
        )

    def test_locked_registry_rejects_callable_that_is_not_module_class(self) -> None:
        registration = AdapterRegistration(
            id='locked-test',
            constructor_module='lib.modules.locked-test',
            constructor_name='constructor',
            verification_schemes=('sha256',),
            trusted_signers=(),
            digest_required=True,
        )
        fake_module = mock.Mock()
        fake_module.constructor = mock.Mock(return_value=object())

        with (
            mock.patch(
                'lib.modules.registry.import_module',
                return_value=fake_module,
            ),
            self.assertRaisesRegex(RuntimeError, 'Invalid locked module constructor'),
        ):
            locked_adapter_factories((registration,))

        fake_module.constructor.assert_not_called()

    def test_exact_legacy_registry_order(self) -> None:
        registry = modules.all_modules()
        self.assertEqual(EXPECTED_MODULES, [module.NAME for module in registry])
        self.assertEqual(EXPECTED_CONSTRUCTORS, registry)

    def test_exact_legacy_cli_order(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(repository_root / 'patch.py'), '--help'],
            check=True,
            capture_output=True,
            text=True,
            cwd=repository_root,
        )

        positions = []
        for name in EXPECTED_MODULES:
            module_option = f'--module-{name} '
            signature_option = f'--module-{name}-sig '
            module_position = result.stdout.index(module_option)
            signature_position = result.stdout.index(signature_option)
            self.assertLess(module_position, signature_position)
            positions.extend([module_position, signature_position])

        self.assertEqual(sorted(positions), positions)

    def test_legacy_help_ignores_corrupt_locked_only_catalog(self) -> None:
        modules.all_modules.cache_clear()
        output = io.StringIO()
        with (
            mock.patch(
                'lib.modules.catalog.load_catalog',
                side_effect=RuntimeError('corrupt locked-only manifest'),
            ) as load,
            mock.patch.object(sys, 'argv', ['patch.py', '--help']),
            redirect_stdout(output),
            self.assertRaises(SystemExit) as raised,
        ):
            patch_script.parse_args()

        self.assertEqual(0, raised.exception.code)
        self.assertIn('--module-bcr', output.getvalue())
        load.assert_not_called()

    def test_hyphenated_locked_id_has_a_safe_destination(self) -> None:
        self.assertEqual('module_test_module', module_argument_dest('test-module'))

    def test_legacy_signature_defaults_to_zip_dot_sig(self) -> None:
        args = argparse.Namespace(
            module_bcr=Path('BCR-release.zip'),
            module_bcr_sig=None,
        )
        with mock.patch.object(modules, 'verify_ssh_sig') as verify:
            module = BCRModule.from_args(args)

        self.assertEqual(Path('BCR-release.zip'), module.zip)
        verify.assert_called_once_with(
            Path('BCR-release.zip'),
            Path('BCR-release.zip.sig'),
            modules.SSH_PUBLIC_KEY_CHENXIAOLONG,
        )


if __name__ == '__main__':
    unittest.main()
