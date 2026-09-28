# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import tomlkit

from lib import modules
from lib.modules.catalog import ModuleCatalog, ModuleSpec
from lib.modules.locks import (
    ArtifactLegal,
    ArtifactLock,
    ArtifactLockFile,
    ApkIdentity,
    ArchiveMember,
    ArchivePolicy,
    LockError,
    ModuleLock,
    cache_path,
    write_lock,
)
from lib.modules.report import AdapterPatchResult
from lib.modules.verified import (
    construct_locked_adapters,
    open_verified_selection,
)
import patch as patch_script


def module_spec() -> ModuleSpec:
    return ModuleSpec.model_validate({
        'schema_version': 2,
        'id': 'locked-test',
        'name': 'Locked test',
        'status': 'supported',
        'adapter': 'locked-test',
        'lifecycle': 'static-image',
        'defaults': {
            'helper_enabled': False,
            'pixene_profile_enabled': False,
        },
        'acknowledgement_required': False,
        'artifact_kinds': ['other'],
        'verification': {
            'schemes': ['sha256'],
            'trust_roots': [],
            'digest_required': True,
            'enforced_by': 'adapter',
        },
        'compatibility': {
            'roms': {'lineageos': {'status': 'supported'}},
            'root_modes': ['rootless'],
            'architectures': ['arm64-v8a'],
        },
        'capabilities': {
            'requires': {
                'selective_signature_spoofing': False,
                'product_priv_app': False,
                'custom_init_selinux': False,
                'abis': ['arm64-v8a'],
                'min_api': 34,
                'max_api': 36,
            },
            'provides': {
                'root': [],
                'zygisk': [],
                'selective_signature_spoofing': False,
                'product_priv_app': False,
                'custom_init_selinux': False,
            },
        },
        'legal': {
            'license': 'Apache-2.0',
            'source_url': 'https://example.com/source',
            'source_offer_required': False,
            'upstream_only_fetching': True,
            'local_only': True,
            'cache_policy': 'read-write',
            'allowed_output_scopes': ['local-unpublished'],
        },
        'dependencies': [],
        'conflicts': [],
        'warnings': [{
            'code': 'fixture-warning',
            'severity': 'warning',
            'message': 'Fixture warning.',
        }],
        'reasons': [],
    })


class LockedPatchBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        self.payload = b'original locked artifact'
        self.artifact = ArtifactLock(
            id='payload',
            kind='other',
            immutable_url='https://downloads.example/v1/payload.bin',
            allowed_origins=('https://downloads.example',),
            version='1',
            size=len(self.payload),
            sha256=hashlib.sha256(self.payload).hexdigest(),
        )
        self.lock = ArtifactLockFile(
            schema_version=1,
            modules=(ModuleLock(
                id='locked-test',
                version='1',
                artifacts=(self.artifact,),
            ),),
        )
        self.lock_path = self.root / 'artifacts.lock.json'
        write_lock(self.lock_path, self.lock)
        self.cache_path = cache_path(self.cache, self.artifact.sha256)
        self.cache_path.parent.mkdir(parents=True)
        self.cache_path.write_bytes(self.payload)
        self.profile_path = self.root / 'profile.toml'
        self.profile_path.write_text(tomlkit.dumps({
            'schema_version': 1,
            'id': 'lineage-fixture',
            'rom_family': 'lineageos',
            'root_mode': 'rootless',
            'abi': 'arm64-v8a',
            'api_level': 35,
            'output_scope': 'local-unpublished',
            'enabled_modules': ['locked-test'],
            'capabilities': {
                'root_providers': [],
                'zygisk_providers': [],
                'selective_signature_spoofing': False,
                'product_priv_app': False,
                'custom_init_selinux': False,
            },
            'acknowledgements': [],
        }), encoding='UTF-8')
        self.catalog = ModuleCatalog((module_spec(),))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_verified_artifact_remains_bound_to_open_inode(self) -> None:
        with open_verified_selection(
            self.catalog,
            self.lock_path,
            self.profile_path,
            self.cache,
            verify_apks=False,
        ) as selection:
            artifact = selection.contexts[0].artifact('payload')
            self.cache_path.unlink()
            self.cache_path.write_bytes(b'replaced unverified bytes')
            with artifact.open() as source:
                self.assertEqual(self.payload, source.read())
            self.assertNotIn(str(self.root), repr(artifact))

    def test_verified_artifact_readers_have_independent_offsets(self) -> None:
        with open_verified_selection(
            self.catalog,
            self.lock_path,
            self.profile_path,
            self.cache,
            verify_apks=False,
        ) as selection:
            artifact = selection.contexts[0].artifact('payload')
            with artifact.open() as first, artifact.open() as second:
                self.assertEqual(self.payload[:5], first.read(5))
                self.assertEqual(self.payload, second.read())
                self.assertEqual(self.payload[5:], first.read())

    def test_artifact_scope_is_enforced_before_adapter_construction(self) -> None:
        restricted = self.artifact.model_copy(update={
            'legal': ArtifactLegal(
                license='Apache-2.0',
                source_offer_required=False,
                allowed_output_scopes=('private',),
            ),
        })
        write_lock(self.lock_path, ArtifactLockFile(
            schema_version=1,
            modules=(ModuleLock(
                id='locked-test',
                version='1',
                artifacts=(restricted,),
            ),),
        ))
        with self.assertRaisesRegex(LockError, 'forbids the selected output scope'):
            open_verified_selection(
                self.catalog,
                self.lock_path,
                self.profile_path,
                self.cache,
                verify_apks=False,
            )

    def test_nested_apk_identity_is_verified_through_anonymous_inode(self) -> None:
        apk_data = b'fixture apk bytes'
        archive_path = self.root / 'container.zip'
        with zipfile.ZipFile(archive_path, 'w') as archive:
            archive.writestr('payload.apk', apk_data)
        identity = ApkIdentity(
            package_name='org.example.fixture',
            version_code=7,
            signer_sha256='ab' * 32,
        )
        archive_artifact = ArtifactLock(
            id='payload',
            kind='zip',
            immutable_url='https://downloads.example/v1/container.zip',
            allowed_origins=('https://downloads.example',),
            version='1',
            size=archive_path.stat().st_size,
            sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            archive=ArchivePolicy(members=(ArchiveMember(
                name='payload.apk',
                size=len(apk_data),
                sha256=hashlib.sha256(apk_data).hexdigest(),
                apk=identity,
            ),)),
        )
        write_lock(self.lock_path, ArtifactLockFile(
            schema_version=1,
            modules=(ModuleLock(
                id='locked-test',
                version='1',
                artifacts=(archive_artifact,),
            ),),
        ))
        nested_cache_path = cache_path(self.cache, archive_artifact.sha256)
        nested_cache_path.parent.mkdir(parents=True, exist_ok=True)
        nested_cache_path.write_bytes(archive_path.read_bytes())

        with mock.patch(
            'lib.modules.verified.verify_apk_identity'
        ) as verify_identity:
            with open_verified_selection(
                self.catalog,
                self.lock_path,
                self.profile_path,
                self.cache,
            ) as selection:
                self.assertEqual(
                    (('payload.apk', 'ab' * 32),),
                    selection.contexts[0].artifacts[0].archive_apk_signers,
                )
                self.assertEqual(
                    [('payload.apk', len(apk_data), hashlib.sha256(apk_data).hexdigest())],
                    [
                        (member.name, member.size, member.sha256)
                        for member in selection.contexts[0].artifacts[0].archive_members
                    ],
                )
                member = selection.contexts[0].artifacts[0].archive_members[0]
                self.assertEqual('org.example.fixture', member.apk_package_name)
                self.assertEqual(7, member.apk_version_code)
                self.assertEqual('ab' * 32, member.apk_signer_sha256)

        verify_identity.assert_called_once()
        verified_path, expected = verify_identity.call_args.args
        self.assertEqual(identity, expected)
        self.assertTrue(str(verified_path).startswith('/proc/self/fd/'))
        self.assertEqual(
            (int(str(verified_path).rsplit('/', 1)[1]),),
            verify_identity.call_args.kwargs['pass_fds'],
        )

    def test_locked_cli_arguments_are_all_or_nothing(self) -> None:
        argv = [
            'patch.py',
            '--input', 'ota.zip',
            '--sign-key-avb', 'avb.key',
            '--sign-key-ota', 'ota.key',
            '--sign-cert-ota', 'ota.crt',
            '--module-lock', 'lock.json',
        ]
        with (
            mock.patch.object(patch_script.modules, 'all_modules', return_value={}),
            mock.patch.object(sys, 'argv', argv),
            self.assertRaises(SystemExit),
        ):
            patch_script.parse_args()

    def test_programmatic_locked_arguments_are_all_or_nothing(self) -> None:
        args = SimpleNamespace(
            module_lock=None,
            module_profile=self.profile_path,
            module_cache=None,
            patch_report=None,
        )
        with (
            mock.patch.object(patch_script.external, 'verify_ota') as verify,
            self.assertRaisesRegex(ValueError, 'one complete set'),
        ):
            patch_script.run(args, self.root / 'work')
        verify.assert_not_called()

    def test_locked_selection_validates_full_catalog(self) -> None:
        args = SimpleNamespace(
            module_lock=self.lock_path,
            module_profile=self.profile_path,
            module_cache=self.cache,
            patch_report=self.root / 'report.json',
            tool_runner_prefix=None,
            pass_avb_env_var=None,
            pass_ota_env_var=None,
        )
        with (
            mock.patch.object(
                patch_script,
                'load_catalog',
                side_effect=RuntimeError('corrupt locked-only manifest'),
            ) as load,
            mock.patch.object(patch_script, '_run') as run,
            self.assertRaisesRegex(RuntimeError, 'corrupt locked-only manifest'),
        ):
            patch_script.run(args, self.root / 'work')

        load.assert_called_once()
        run.assert_not_called()

    def test_legacy_run_does_not_validate_locked_catalog(self) -> None:
        args = SimpleNamespace(
            module_lock=None,
            module_profile=None,
            module_cache=None,
            patch_report=None,
            tool_runner_prefix=None,
            pass_avb_env_var=None,
            pass_ota_env_var=None,
        )
        with (
            mock.patch.object(
                patch_script,
                'load_catalog',
                side_effect=RuntimeError('missing locked-only manifest'),
            ) as load,
            mock.patch.object(
                patch_script,
                '_run',
                return_value='legacy-result',
            ) as run,
        ):
            result = patch_script.run(args, self.root / 'work')

        self.assertEqual('legacy-result', result)
        load.assert_not_called()
        run.assert_called_once_with(args, self.root / 'work', None, ())

    def test_untrusted_callable_factory_is_not_invoked(self) -> None:
        invoked = False

        def untrusted(context):
            nonlocal invoked
            invoked = True
            return object()

        with open_verified_selection(
            self.catalog,
            self.lock_path,
            self.profile_path,
            self.cache,
            verify_apks=False,
        ) as selection:
            with self.assertRaisesRegex(RuntimeError, 'invalid module'):
                construct_locked_adapters(
                    selection,
                    {'locked-test': untrusted},
                )
        self.assertFalse(invoked)

    def test_injected_filesystem_root_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, 'invalid injected Android path'):
            AdapterPatchResult(('/',))

    def test_path_statuses_must_exactly_match_injected_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, 'exactly match'):
            AdapterPatchResult(
                ('/system/app/Fixture/Fixture.apk',),
                (('/system/app/Other/Other.apk', 'created'),),
            )

    def test_adapter_is_constructed_before_ota_work_and_report_is_stable(self) -> None:
        events: list[str] = []

        class TestAdapter(modules.Module):
            def __init__(self, context) -> None:
                events.append('construct')
                self.context = context

            def requirements(self) -> modules.ModuleRequirements:
                return modules.ModuleRequirements(set(), set(), False)

            def inject(
                self,
                boot_fs,
                ext_fs,
                sepolicies,
                compatible_sepolicy=False,
            ) -> AdapterPatchResult:
                events.append('inject')
                with self.context.artifact('payload').open() as source:
                    if source.read() != self.payload:
                        raise AssertionError('adapter did not receive verified bytes')
                return AdapterPatchResult(('/system/app/Fixture/Fixture.apk',))

        TestAdapter.payload = self.payload
        report_path = self.root / 'reports' / 'patch.json'
        args = SimpleNamespace(
            input=self.root / 'input.zip',
            output=self.root / 'output.zip',
            verify_public_key_avb=None,
            verify_cert_ota=None,
            sign_key_avb=self.root / 'avb.key',
            sign_key_ota=self.root / 'ota.key',
            sign_cert_ota=self.root / 'ota.crt',
            pass_avb_env_var=None,
            pass_ota_env_var=None,
            pass_avb_file=None,
            pass_ota_file=None,
            patch_arg=['--rootless'],
            skip_custota_tool=True,
            compatible_sepolicy=False,
            module_lock=self.lock_path,
            module_profile=self.profile_path,
            module_cache=self.cache,
            patch_report=report_path,
        )

        def verify_ota(*unused) -> None:
            events.append('verify-ota')

        real_build_patch_report = patch_script.build_patch_report

        def build_report(*arguments):
            events.append('build-report')
            return real_build_patch_report(*arguments)

        def patch_ota(*unused) -> None:
            events.append('patch-ota')

        with (
            mock.patch.object(patch_script, 'load_catalog', return_value=self.catalog),
            mock.patch.object(
                patch_script,
                'locked_adapter_factories',
                return_value={'locked-test': TestAdapter},
            ),
            mock.patch.object(patch_script.modules, 'all_modules', return_value={}),
            mock.patch.object(
                patch_script.external,
                'verify_ota',
                side_effect=verify_ota,
            ),
            mock.patch.object(
                patch_script,
                'build_patch_report',
                side_effect=build_report,
            ),
            mock.patch.object(
                patch_script.external,
                'patch_ota',
                side_effect=patch_ota,
            ),
        ):
            patch_script.run(args, self.root / 'work')

        self.assertEqual(
            ['construct', 'verify-ota', 'inject', 'build-report', 'patch-ota'],
            events,
        )
        report = json.loads(report_path.read_text(encoding='UTF-8'))
        self.assertEqual(['locked-test'], report['selected_modules'])
        self.assertEqual(self.artifact.sha256, report['artifacts'][0]['sha256'])
        self.assertEqual(
            '/system/app/Fixture/Fixture.apk',
            report['injected_paths'][0]['path'],
        )
        self.assertEqual('fixture-warning', report['warnings'][0]['code'])
        self.assertTrue(report_path.read_bytes().endswith(b'\n'))
        self.assertEqual([], list(report_path.parent.glob('*.tmp')))

    def test_invalid_adapter_is_rejected_before_ota_verification(self) -> None:
        args = SimpleNamespace(
            module_lock=self.lock_path,
            module_profile=self.profile_path,
            module_cache=self.cache,
            patch_report=self.root / 'patch.json',
        )
        with (
            mock.patch.object(patch_script, 'load_catalog', return_value=self.catalog),
            mock.patch.object(
                patch_script,
                'locked_adapter_factories',
                return_value={'locked-test': lambda context: object()},
            ),
            mock.patch.object(patch_script.external, 'verify_ota') as verify,
            self.assertRaisesRegex(RuntimeError, 'invalid module'),
        ):
            patch_script.run(args, self.root / 'work')
        verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
