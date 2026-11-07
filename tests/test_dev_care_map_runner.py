"""Behavioral checks for the development source authorization boundary."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools' / 'care-map'
MODOS = Path(os.environ.get('MODOS_REPO', '/workspace/work/lineage-integration'))


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DevelopmentRunnerTests(unittest.TestCase):
    def test_sealed_execution_rejects_replaced_bytes_despite_forged_receipt(self):
        if not (MODOS / 'src' / 'bootstrap_archive.py').is_file():
            self.skipTest('ModOS bootstrap source required for Linux memfd integration')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            binary = work / 'candidate'
            shutil.copyfile('/bin/echo', binary)
            data = binary.read_bytes()
            prefix = ['/usr/bin/python3', str(TOOLS / 'dev_tool_runner.py'),
                '--modos-repo', str(MODOS), '--bootstrap-workdir', str(work),
                '--built-binary', str(binary), '--built-sha256', hashlib.sha256(data).hexdigest(),
                '--built-size', str(len(data)), 'avbroot', '--']
            accepted = subprocess.run([*prefix, 'literal;$(never-run)'], capture_output=True, text=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.strip(), 'literal;$(never-run)')
            changed = bytearray(data)
            changed[-1] ^= 1
            binary.write_bytes(changed)
            (work / 'build-receipt.json').write_text(json.dumps({
                'binary_sha256': hashlib.sha256(changed).hexdigest(), 'binary_size': len(changed)}))
            rejected = subprocess.run([*prefix, 'should-not-execute'], capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout, '')
            self.assertIn('does not match', rejected.stderr)

    def test_parent_preserves_tool_arguments_and_delegates_other_tools(self):
        runner = load('dev_tool_runner')
        args = runner.parse_args(['--modos-repo', '/trusted/modos',
            '--bootstrap-workdir', '/work/bootstrap', '--built-binary', '/work/candidate',
            '--built-sha256', '0' * 64, '--built-size', '1', 'avbroot', '--', '--', '--version'])
        self.assertEqual(args.arguments, ['--', '--version'])
        # Existing production bootstrap owns afsr/custota executable trust.
        if not (MODOS / 'src' / 'bootstrap_archive.py').is_file():
            self.skipTest('ModOS bootstrap source required for delegation test')
        args.modos_repo = MODOS
        args.tool = 'afsr'
        args.arguments = ['unpack', '--input', '/file with spaces']
        with mock.patch.object(runner.os, 'execve', side_effect=RuntimeError('intercepted')) as execution:
            with self.assertRaisesRegex(RuntimeError, 'intercepted'):
                runner.execute(args)
        self.assertEqual(execution.call_args.args[1][-5:], ['afsr', '--', 'unpack', '--input', '/file with spaces'])
        self.assertIn(str(MODOS / 'src' / 'bootstrap_executable_tools.py'), execution.call_args.args[1])

    def test_unreviewed_source_changes_fail_before_build(self):
        builder = load('build_and_run')
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            source = repository / 'tools' / 'care-map'
            source.mkdir(parents=True)
            patch = source / 'avbroot-runtime-care-map.patch'
            patch.write_bytes(b'reviewed patch')
            manifest = source / 'source-build.json'
            manifest.write_text(json.dumps({'schema': 'avbroot-development-source-v1',
                'repository': 'https://github.com/chenxiaolong/avbroot.git',
                'base_commit': '1' * 40, 'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest(),
                'cargo_lock_sha256': '2' * 64, 'rust_toolchain': '1.99.0'}))
            script = source / 'build_and_run.py'
            script.write_text('reviewed builder')
            (source / 'dev_tool_runner.py').write_text('reviewed runner')
            subprocess.run(['git', 'init', '-q', str(repository)], check=True)
            subprocess.run(['git', '-C', str(repository), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(repository), '-c', 'user.name=test',
                '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'reviewed source'], check=True)
            with mock.patch.multiple(builder, HELPER=repository, DIRECTORY=source,
                MANIFEST=manifest, PATCH=patch, __file__=str(script)):
                self.assertEqual(builder.load_source()[0]['patch_sha256'], hashlib.sha256(patch.read_bytes()).hexdigest())
                patch.write_bytes(b'unreviewed replacement')
                with self.assertRaises(subprocess.CalledProcessError):
                    builder.load_source()


    def test_fresh_build_discards_intermediates_and_retains_executable_authorization(self):
        if not (MODOS / 'src' / 'bootstrap_archive.py').is_file():
            self.skipTest('ModOS bootstrap source required for Linux memfd integration')
        builder = load('build_and_run')
        for supplied_cargo, supplied_rustup in ((False, False), (True, False), (False, True), (True, True), ('shared', False)):
            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory) / 'fresh-build'
                lock = b'reviewed lock bytes'
                manifest = {'repository': 'https://github.com/chenxiaolong/avbroot.git',
                            'base_commit': '1' * 40, 'rust_toolchain': '1.99.0',
                            'cargo_lock_sha256': hashlib.sha256(lock).hexdigest()}
                explicit_cargo = ((work / 'rustup-home' / 'caller-cargo') if supplied_cargo == 'shared'
                                  else Path(directory) / 'caller-cargo') if supplied_cargo else None
                explicit_rustup = Path(directory) / 'caller-rustup' if supplied_rustup else None
                args = argparse.Namespace(modos_repo=MODOS, build_workdir=work,
                    bootstrap_workdir=work, cargo_home=explicit_cargo, rustup_home=explicit_rustup)

                # Replace compilation only: cleanup and the retained executable's
                # actual sealed execution remain real, without another Rust build.
                def compile_step(command, **kwargs):
                    for key in ('CARGO_HOME', 'RUSTUP_HOME'):
                        (Path(kwargs['env'][key]) / 'retained-cache-marker').write_bytes(b'compiler cache')
                    if command[:2] == ['git', 'clone']:
                        checkout = Path(command[-1])
                        (checkout / '.git').mkdir(parents=True)
                        (checkout / 'Cargo.lock').write_bytes(lock)
                    elif Path(command[0]).name == 'cargo' and command[1] == 'build':
                        target = kwargs['cwd'] / 'target' / 'release'
                        target.mkdir(parents=True)
                        shutil.copyfile('/bin/echo', target / 'avbroot')
                        (target / 'discard-me').write_bytes(b'compilation intermediate')

                with mock.patch.object(builder, 'load_source', return_value=(manifest, b'patch', 'reviewed')), \
                     mock.patch.object(builder, 'require_clean'), \
                     mock.patch.object(builder.subprocess, 'run', side_effect=compile_step), \
                     mock.patch.object(builder, 'pinned_compiler', return_value=(Path('/pinned/cargo'), Path('/pinned/rustc'))), \
                     mock.patch.object(builder.subprocess, 'check_output', side_effect=['rustc provenance', 'cargo provenance']):
                    prefix, receipt = builder.build_prefix(args)
                binary = work / 'avbroot'
                self.assertFalse((work / 'source').exists())
                for explicit, name in ((explicit_cargo, 'cargo-home'), (explicit_rustup, 'rustup-home')):
                    if explicit is None:
                        retained_for_caller = supplied_cargo == 'shared' and name == 'rustup-home'
                        self.assertEqual((work / name).exists(), retained_for_caller)
                    else:
                        self.assertEqual((explicit / 'retained-cache-marker').read_bytes(), b'compiler cache')
                self.assertTrue((work / 'build-receipt.json').is_file())
                self.assertEqual(receipt['binary_sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
                self.assertEqual(prefix[prefix.index('--built-binary') + 1], str(binary))
                accepted = subprocess.run([*prefix, 'avbroot', '--', 'retained bytes'],
                                          capture_output=True, text=True)
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                self.assertEqual(accepted.stdout.strip(), 'retained bytes')

    def test_build_scripts_receive_no_signing_secrets_or_compiler_overrides(self):
        builder = load('build_and_run')
        with mock.patch.dict(builder.os.environ, {'PASSPHRASE_OTA': 'private',
            'KEYS_AVB_BASE64': 'private', 'GH_TOKEN': 'private',
            'RUSTC_WRAPPER': '/unreviewed-wrapper', 'RUSTC': '/unreviewed-compiler', 'HTTPS_PROXY': 'https://session-proxy'}):
            environment = builder.compiler_environment(Path('/work/cargo'), Path('/work/rustup'), '1.99.0')
        for secret in ('PASSPHRASE_OTA', 'KEYS_AVB_BASE64', 'GH_TOKEN', 'RUSTC_WRAPPER', 'RUSTC'):
            self.assertNotIn(secret, environment)
        self.assertEqual(environment['HTTPS_PROXY'], 'https://session-proxy')
        self.assertEqual(environment['CARGO_HOME'], '/work/cargo')

    def test_caller_cannot_override_parent_runner_or_reuse_existing_build(self):
        builder = load('build_and_run')
        with mock.patch.object(builder, 'build_prefix') as build:
            with self.assertRaises(SystemExit):
                builder.main(['--modos-repo', '/modos', '--bootstrap-workdir', '/bootstrap',
                    '--build-workdir', '/new', '--', '--tool-runner-prefix-json=["evil"]'])
            build.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            args = argparse.Namespace(modos_repo=work, build_workdir=work,
                bootstrap_workdir=work, cargo_home=None, rustup_home=None)
            with mock.patch.object(builder, 'load_source', return_value=({}, b'', 'reviewed')), mock.patch.object(builder, 'require_clean'):
                with self.assertRaises(FileExistsError):
                    builder.build_prefix(args)


if __name__ == '__main__':
    unittest.main()
