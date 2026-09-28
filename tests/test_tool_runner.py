# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

from lib import external
import patch as patch_script


PREFIX = (
    '/usr/bin/python3',
    '/opt/pixene/bootstrap.py',
    '--workdir',
    '/var/tmp/pixene-work',
    'run',
)


class ToolRunnerTest(unittest.TestCase):
    def tearDown(self) -> None:
        external.configure_tool_runner(None)

    def test_legacy_runner_preserves_bare_tools_and_cwd(self) -> None:
        cases = (
            (
                lambda: external.verify_ota(Path('ota.zip'), None, None),
                ['avbroot', 'ota', 'verify', '--input', 'ota.zip'],
                None,
            ),
            (
                lambda: external.unpack_avb(Path('boot.img'), Path('work')),
                [
                    'avbroot', 'avb', 'unpack', '--quiet', '--input',
                    str(Path('boot.img').absolute()),
                ],
                Path('work'),
            ),
            (
                lambda: external.unpack_fs(Path('system.img'), Path('work')),
                [
                    'afsr', 'unpack', '--input',
                    str(Path('system.img').absolute()),
                ],
                Path('work'),
            ),
            (
                lambda: external.generate_update_info(
                    Path('pdx235.json'), 'ota.zip'
                ),
                [
                    'custota-tool', 'gen-update-info', '--file',
                    'pdx235.json', '--location', 'ota.zip',
                ],
                None,
            ),
            (
                lambda: external.generate_csig(
                    Path('ota.zip'),
                    external.SigningKey(
                        Path('ota.key'), 'SIGNING_PASSWORD', None
                    ),
                    Path('ota.crt'),
                ),
                [
                    'custota-tool', 'gen-csig', '--input', 'ota.zip', '--key',
                    'ota.key', '--cert', 'ota.crt', '--passphrase-env-var',
                    'SIGNING_PASSWORD',
                ],
                None,
            ),
        )

        for invoke, expected_argv, expected_cwd in cases:
            with self.subTest(tool=expected_argv[0]):
                with mock.patch('lib.external.subprocess.check_call') as call:
                    invoke()

                kwargs = {'cwd': expected_cwd} if expected_cwd is not None else {}
                call.assert_called_once_with(expected_argv, **kwargs)

    def test_prefixed_runner_uses_separator_exact_argv_and_cwd(self) -> None:
        external.configure_tool_runner(PREFIX)
        cases = (
            (
                lambda: external.verify_ota(Path('ota.zip'), None, None),
                ['avbroot', 'ota', 'verify', '--input', 'ota.zip'],
                None,
            ),
            (
                lambda: external.unpack_avb(Path('boot.img'), Path('work')),
                [
                    'avbroot', 'avb', 'unpack', '--quiet', '--input',
                    str(Path('boot.img').absolute()),
                ],
                Path('work'),
            ),
            (
                lambda: external.unpack_fs(Path('system.img'), Path('work')),
                [
                    'afsr', 'unpack', '--input',
                    str(Path('system.img').absolute()),
                ],
                Path('work'),
            ),
            (
                lambda: external.generate_update_info(
                    Path('pdx235.json'), 'ota.zip'
                ),
                [
                    'custota-tool', 'gen-update-info', '--file',
                    'pdx235.json', '--location', 'ota.zip',
                ],
                None,
            ),
            (
                lambda: external.generate_csig(
                    Path('ota.zip'),
                    external.SigningKey(
                        Path('ota.key'), 'SIGNING_PASSWORD', None
                    ),
                    Path('ota.crt'),
                ),
                [
                    'custota-tool', 'gen-csig', '--input', 'ota.zip', '--key',
                    'ota.key', '--cert', 'ota.crt', '--passphrase-env-var',
                    'SIGNING_PASSWORD',
                ],
                None,
            ),
        )

        for invoke, tool_argv, expected_cwd in cases:
            with self.subTest(tool=tool_argv[0]):
                with mock.patch('lib.external.subprocess.check_call') as call:
                    invoke()

                expected = [*PREFIX, tool_argv[0], '--', *tool_argv[1:]]
                kwargs = call.call_args.kwargs
                self.assertEqual(expected_cwd, kwargs.get('cwd'))
                self.assertNotIn('LD_PRELOAD', kwargs['env'])
                self.assertNotIn('PYTHONPATH', kwargs['env'])
                expected_kwargs = {'env': mock.ANY}
                if expected_cwd is not None:
                    expected_kwargs['cwd'] = expected_cwd
                call.assert_called_once_with(expected, **expected_kwargs)

    def test_injection_shaped_argument_is_literal_and_never_a_shell(self) -> None:
        external.configure_tool_runner(PREFIX)
        location = '$(touch /tmp/never); --tool afsr | sh'

        with mock.patch('lib.external.subprocess.check_call') as call:
            external.generate_update_info(Path('report.json'), location)

        argv = call.call_args.args[0]
        self.assertEqual(location, argv[-1])
        self.assertNotIn('shell', call.call_args.kwargs)

    def test_prefix_json_is_an_exact_bounded_argv_sequence(self) -> None:
        value = external.parse_tool_runner_prefix_json(
            '["/usr/bin/python3","/opt/bootstrap.py","run"]'
        )
        self.assertEqual(
            ('/usr/bin/python3', '/opt/bootstrap.py', 'run'),
            value,
        )

    def test_malformed_prefix_fails_before_subprocess_without_fallback(self) -> None:
        invalid = (
            'not-json',
            '"/usr/bin/python3"',
            '["python3","bootstrap.py"]',
            '["/usr/bin/python3",""]',
            '["/usr/bin/python3","bad\\u0000arg"]',
            '["/usr/bin/python3","bad\\narg"]',
            '["/usr/bin/python3","bad\\u001farg"]',
            '["/usr/bin/python3","bad\\u007farg"]',
            '["/usr/bin/python3","--"]',
        )

        with mock.patch('lib.external.subprocess.check_call') as call:
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    external.parse_tool_runner_prefix_json(value)
            for prefix in (
                ('/usr/bin/python3', 'bad\narg'),
                ('/usr/bin/python3', '--'),
            ):
                with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                    external.configure_tool_runner(prefix)

        call.assert_not_called()

    def test_patch_cli_rejects_malformed_prefix_before_subprocess(self) -> None:
        secret = 'not-json-SUPER-SECRET-RUNNER-TOKEN'
        argv = [
            'patch.py',
            '--input', 'ota.zip',
            '--sign-key-avb', 'avb.key',
            '--sign-key-ota', 'ota.key',
            '--sign-cert-ota', 'ota.crt',
            '--tool-runner-prefix-json', secret,
        ]
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, 'argv', argv),
            mock.patch('lib.external.subprocess.check_call') as call,
            redirect_stderr(stderr),
            self.assertRaises(SystemExit),
        ):
            patch_script.parse_args()
        call.assert_not_called()
        self.assertNotIn(secret, stderr.getvalue())
        self.assertIn(
            '--tool-runner-prefix-json is invalid',
            stderr.getvalue(),
        )

    def test_configure_rejects_unknown_tool_without_subprocess(self) -> None:
        external.configure_tool_runner(PREFIX)
        with (
            mock.patch('lib.external.subprocess.check_call') as call,
            self.assertRaisesRegex(ValueError, 'unsupported external tool'),
        ):
            external.run_tool('sh', ('-c', 'exit 0'))
        call.assert_not_called()

    def test_prefixed_runner_preserves_signing_environment_only(self) -> None:
        external.configure_tool_runner(
            PREFIX,
            signing_environment_names=('AVB_PASSWORD', 'OTA_PASSWORD'),
        )
        environment = {
            'AVB_PASSWORD': 'avb-preserved',
            'OTA_PASSWORD': 'ota-preserved',
            'LD_PRELOAD': '/tmp/inject.so',
            'PYTHONPATH': '/tmp/inject',
            'PATH': os.environ.get('PATH', ''),
        }
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch('lib.external.subprocess.check_call') as call,
        ):
            external.verify_ota(Path('ota.zip'), None, None)

        child_env = call.call_args.kwargs['env']
        self.assertEqual('avb-preserved', child_env['AVB_PASSWORD'])
        self.assertEqual('ota-preserved', child_env['OTA_PASSWORD'])
        self.assertNotIn('LD_PRELOAD', child_env)
        self.assertNotIn('PYTHONPATH', child_env)

    def test_prefixed_signing_routes_preserve_exact_argv_cwd_and_env(
        self,
    ) -> None:
        external.configure_tool_runner(
            PREFIX,
            signing_environment_names=('AVB_PASSWORD', 'OTA_PASSWORD'),
        )
        environment = {
            'AVB_PASSWORD': 'avb-preserved',
            'OTA_PASSWORD': 'ota-preserved',
            'LD_PRELOAD': '/tmp/inject.so',
        }
        cases = (
            (
                lambda: external.patch_ota(
                    Path('input.zip'),
                    Path('output.zip'),
                    external.SigningKey(
                        Path('avb.key'), 'AVB_PASSWORD', None
                    ),
                    external.SigningKey(
                        Path('ota.key'), 'OTA_PASSWORD', None
                    ),
                    Path('ota.crt'),
                    {'system': Path('system.img')},
                    ('--rootless',),
                ),
                [
                    'avbroot', 'ota', 'patch', '--input', 'input.zip',
                    '--output', 'output.zip', '--key-avb', 'avb.key',
                    '--key-ota', 'ota.key', '--cert-ota', 'ota.crt',
                    '--rootless', '--pass-avb-env-var', 'AVB_PASSWORD',
                    '--pass-ota-env-var', 'OTA_PASSWORD', '--replace',
                    'system', 'system.img',
                ],
                None,
            ),
            (
                lambda: external.pack_avb(
                    Path('system.img'),
                    Path('work'),
                    external.SigningKey(
                        Path('relative/avb.key'),
                        None,
                        Path('relative/avb.pass'),
                    ),
                    True,
                ),
                [
                    'avbroot', 'avb', 'pack', '--quiet', '--output',
                    str(Path('system.img').absolute()), '--key',
                    str(Path('relative/avb.key').absolute()), '--pass-file',
                    str(Path('relative/avb.pass').absolute()),
                    '--recompute-size',
                ],
                Path('work'),
            ),
        )

        for invoke, tool_argv, expected_cwd in cases:
            with self.subTest(arguments=tool_argv[1:]), (
                mock.patch.dict(os.environ, environment, clear=True)
            ), mock.patch('lib.external.subprocess.check_call') as call:
                invoke()

            expected = [*PREFIX, tool_argv[0], '--', *tool_argv[1:]]
            kwargs = call.call_args.kwargs
            self.assertEqual(expected_cwd, kwargs.get('cwd'))
            self.assertEqual('avb-preserved', kwargs['env']['AVB_PASSWORD'])
            self.assertEqual('ota-preserved', kwargs['env']['OTA_PASSWORD'])
            self.assertNotIn('LD_PRELOAD', kwargs['env'])
            expected_kwargs = {'env': mock.ANY}
            if expected_cwd is not None:
                expected_kwargs['cwd'] = expected_cwd
            call.assert_called_once_with(expected, **expected_kwargs)

    def test_unsafe_selected_signing_environment_fails_before_subprocess(
        self,
    ) -> None:
        with (
            mock.patch('lib.external.subprocess.check_call') as call,
            self.assertRaisesRegex(ValueError, 'unsafe signing passphrase'),
        ):
            external.configure_tool_runner(
                PREFIX,
                signing_environment_names=('LD_PRELOAD',),
            )
        call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
