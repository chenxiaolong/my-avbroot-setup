# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from lib.modules import cli
from lib.modules.locks import (
    ArtifactLock,
    ArtifactLockFile,
    ModuleLock,
    cache_path,
    write_lock,
)


class ModuleCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'

        self.payload = b'locked artifact bytes'
        artifact = ArtifactLock(
            id='payload',
            kind='other',
            immutable_url='https://downloads.example/releases/v1/payload.bin',
            allowed_origins=('https://downloads.example',),
            version='v1',
            size=len(self.payload),
            sha256=hashlib.sha256(self.payload).hexdigest(),
        )
        self.lock = ArtifactLockFile(
            schema_version=1,
            modules=(ModuleLock(
                id='alpha',
                version='1',
                artifacts=(artifact,),
            ),),
        )
        self.lock_path = self.root / 'artifacts.lock.json'
        write_lock(self.lock_path, self.lock)

        self.cached_path = cache_path(self.cache, artifact.sha256)
        self.cached_path.parent.mkdir(parents=True)
        self.cached_path.write_bytes(self.payload)
        self.cached_path.chmod(0o444)

        self.archive_path = self.root / 'fixture.zip'
        with zipfile.ZipFile(self.archive_path, 'w') as archive:
            archive.writestr('payload.txt', b'archive payload')

        self.profile_path = self.root / 'profile.toml'
        self.profile_path.write_text(
            """schema_version = 1
id = 'empty-lineage-fixture'
rom_family = 'lineageos'
root_mode = 'rootless'
abi = 'arm64-v8a'
api_level = 35
output_scope = 'local-unpublished'
enabled_modules = []

[capabilities]
root_providers = []
zygisk_providers = []
selective_signature_spoofing = false
product_priv_app = false
custom_init_selinux = false
""",
            encoding='UTF-8',
        )

    def run_cli(self, *arguments: str) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            cli.main(list(arguments))
        return output.getvalue()

    def test_phase_one_command_surface_is_deterministic_and_offline(self) -> None:
        with (
            mock.patch.object(cli, '_update_lock') as update_lock,
            mock.patch(
                'lib.modules.locks.build_opener',
                side_effect=AssertionError('offline command attempted network access'),
            ) as build_opener,
        ):
            catalog = json.loads(self.run_cli(
                'catalog', 'list', '--format', 'json'
            ))
            self.assertEqual(2, catalog['schema_version'])

            verified_lock = json.loads(self.run_cli(
                'lock', 'verify', '--lock', str(self.lock_path)
            ))
            self.assertEqual(self.lock.model_dump(mode='json'), verified_lock)

            expected_paths = [str(self.cached_path)]
            fetched = json.loads(self.run_cli(
                'artifacts', 'fetch',
                '--lock', str(self.lock_path),
                '--cache', str(self.cache),
                '--module', 'alpha',
            ))
            self.assertEqual(expected_paths, fetched)

            verified = json.loads(self.run_cli(
                'artifacts', 'verify',
                '--lock', str(self.lock_path),
                '--cache', str(self.cache),
                '--module', 'alpha',
            ))
            self.assertEqual(expected_paths, verified)

            inspection = json.loads(self.run_cli(
                'artifacts', 'inspect', str(self.archive_path),
                '--allow', 'payload.txt',
            ))
            self.assertEqual(['payload.txt'], [
                member['name'] for member in inspection['members']
            ])

            resolution = json.loads(self.run_cli(
                'resolve',
                '--profile', str(self.profile_path),
                '--lock', str(self.lock_path),
                '--format', 'json',
            ))
            self.assertEqual([], resolution['selected_modules'])
            self.assertEqual('empty-lineage-fixture', resolution['profile'])
            self.assertEqual(
                hashlib.sha256(self.lock_path.read_bytes()).hexdigest(),
                resolution['lock_sha256'],
            )

        update_lock.assert_not_called()
        build_opener.assert_not_called()

    def test_lock_update_without_provider_fails_clearly(self) -> None:
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            cli.main(['lock', 'update', 'alpha'])

        self.assertEqual(2, raised.exception.code)
        self.assertIn(
            'no reviewed lock-update provider is available for module: alpha',
            errors.getvalue(),
        )
        self.assertNotIn('Traceback', errors.getvalue())

    def test_local_lock_consumers_reject_noncanonical_json(self) -> None:
        self.lock_path.write_text(
            json.dumps(self.lock.model_dump(mode='json')),
            encoding='UTF-8',
        )
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            cli.main(['lock', 'verify', '--lock', str(self.lock_path)])

        self.assertEqual(2, raised.exception.code)
        self.assertIn('not canonical JSON', errors.getvalue())

        for arguments in (
            (
                'artifacts', 'fetch', '--lock', str(self.lock_path),
                '--cache', str(self.cache),
            ),
            (
                'artifacts', 'verify', '--lock', str(self.lock_path),
                '--cache', str(self.cache),
            ),
        ):
            with self.subTest(command=arguments[:2]):
                errors = io.StringIO()
                with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
                    cli.main(list(arguments))
                self.assertEqual(2, raised.exception.code)
                self.assertIn('not canonical JSON', errors.getvalue())

        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            cli.main([
                'resolve',
                '--profile', str(self.profile_path),
                '--lock', str(self.lock_path),
            ])
        self.assertEqual(2, raised.exception.code)
        self.assertIn('not canonical JSON', errors.getvalue())

    def test_archive_limits_must_be_positive(self) -> None:
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            cli.main([
                'artifacts', 'inspect', str(self.archive_path),
                '--allow', 'payload.txt',
                '--max-members', '0',
            ])

        self.assertEqual(2, raised.exception.code)
        self.assertIn('must be a positive integer', errors.getvalue())
        self.assertNotIn('Traceback', errors.getvalue())

    def test_module_arguments_are_canonical_and_not_reflected(self) -> None:
        unsafe = 'alpha\nunsafe'
        for arguments in (
            ('lock', 'update', unsafe),
            (
                'artifacts', 'verify', '--lock', str(self.lock_path),
                '--cache', str(self.cache), '--module', unsafe,
            ),
        ):
            with self.subTest(command=arguments[:2]):
                errors = io.StringIO()
                with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
                    cli.main(list(arguments))
                self.assertEqual(2, raised.exception.code)
                self.assertIn('must be a canonical module ID', errors.getvalue())
                self.assertNotIn(unsafe, errors.getvalue())

    def test_invalid_profile_does_not_reflect_unknown_secret_values(self) -> None:
        secret = 'SUPERSECRET'
        with self.profile_path.open('a', encoding='UTF-8') as output:
            output.write(f"\napi_token = '{secret}'\n")
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            cli.main([
                'resolve', '--profile', str(self.profile_path),
                '--lock', str(self.lock_path),
            ])
        self.assertEqual(2, raised.exception.code)
        self.assertIn('invalid resolution profile', errors.getvalue())
        self.assertNotIn(secret, errors.getvalue())
        self.assertNotIn('Traceback', errors.getvalue())


if __name__ == '__main__':
    unittest.main()
