# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

import tomlkit

from lib.modules.catalog import (
    CatalogError,
    VerificationPolicy,
    load_catalog,
    migrate_v1_manifest,
)
from lib.modules.registry import AdapterRegistration


MANIFEST = """
schema_version = 1
id = '{id}'
name = '{name}'
status = 'supported'
adapter = '{adapter}'
default_enabled = false
artifact_kinds = ['native-image-module-zip']
dependencies = []
conflicts = []
warnings = []
reasons = []

[verification]
schemes = ['ssh-signature']
trusted_signers = ['test-signer']
digest_required = false
enforced_by = 'adapter'

[compatibility]
rom_families = ['unknown']
root_modes = ['unknown']
architectures = ['unknown']
"""


MANIFEST_V2 = """
schema_version = 2
id = '{id}'
name = '{name}'
status = 'supported'
adapter = '{adapter}'
lifecycle = 'custom-init'
acknowledgement_required = false
artifact_kinds = ['native-image-module-zip']
dependencies = []
conflicts = []
warnings = []
reasons = []

[defaults]
helper_enabled = false
pixene_profile_enabled = false

[verification]
schemes = ['ssh-signature']
digest_required = false
enforced_by = 'adapter'

[[verification.trust_roots]]
type = 'ssh-key-sha256'
value = 'test-signer'

[compatibility]
root_modes = ['rootless']
architectures = ['arm64-v8a']

[compatibility.roms.lineageos]
status = 'supported'

[capabilities.requires]
root_provider = 'any'
zygisk_provider = 'zygisk-next'
selective_signature_spoofing = true
product_priv_app = true
custom_init_selinux = true
abis = ['arm64-v8a']
min_api = 34
max_api = 36

[capabilities.provides]
root = ['magisk']
zygisk = ['zygisk-next']
selective_signature_spoofing = false
product_priv_app = false
custom_init_selinux = true

[legal]
license = 'GPL-3.0-or-later'
source_url = 'https://example.invalid/source'
source_offer_required = true
upstream_only_fetching = true
local_only = true
cache_policy = 'read-write'
allowed_output_scopes = ['local-unpublished']
"""


def registration(id: str) -> AdapterRegistration:
    return AdapterRegistration(
        id=id,
        constructor_module=f'lib.modules.{id}',
        constructor_name=f'{id.title()}Module',
        verification_schemes=('ssh-signature',),
        trusted_signers=('test-signer',),
        digest_required=False,
    )


class ModuleCatalogTest(unittest.TestCase):
    def write_manifest(
        self,
        directory: Path,
        filename: str,
        *,
        id: str,
        adapter: str,
        name: str | None = None,
    ) -> None:
        content = MANIFEST.format(
            id=id,
            adapter=adapter,
            name=name or id,
        )
        (directory / filename).write_text(
            textwrap.dedent(content),
            encoding='UTF-8',
        )

    def write_v2_manifest(
        self,
        directory: Path,
        filename: str,
        *,
        id: str,
        adapter: str,
        name: str | None = None,
    ) -> None:
        content = MANIFEST_V2.format(
            id=id,
            adapter=adapter,
            name=name or id,
        )
        (directory / filename).write_text(
            textwrap.dedent(content),
            encoding='UTF-8',
        )

    def test_catalog_is_ordered_by_canonical_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'zeta.toml', id='zeta', adapter='zeta'
            )
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )

            catalog = load_catalog(
                directory,
                registrations=(registration('alpha'), registration('zeta')),
            )

            self.assertEqual(['alpha', 'zeta'], [m.id for m in catalog.modules])

    def test_duplicate_ids_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            self.write_manifest(
                directory, 'zeta.toml', id='alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Duplicate module ID'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_unknown_adapter_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='arbitrary-import'
            )

            with self.assertRaisesRegex(CatalogError, 'unknown adapter'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_invalid_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='Alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_json_is_stable_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            catalog = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            )

            first = catalog.as_json()
            second = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            ).as_json()

            self.assertEqual(first, second)
            self.assertTrue(first.endswith('\n'))
            parsed = json.loads(first)
            self.assertEqual(2, parsed['schema_version'])
            self.assertEqual('alpha', parsed['modules'][0]['id'])

    def test_schema_v1_migration_is_deterministic_and_conservative(self) -> None:
        raw = tomlkit.loads(
            textwrap.dedent(
                MANIFEST.format(id='alpha', adapter='alpha', name='alpha')
            )
        ).unwrap()
        raw['default_enabled'] = True

        first = migrate_v1_manifest(raw)
        second = migrate_v1_manifest(raw)

        self.assertEqual(first, second)
        self.assertEqual(2, first['schema_version'])
        self.assertEqual('static-image', first['lifecycle'])
        self.assertEqual(
            {
                'helper_enabled': True,
                'pixene_profile_enabled': False,
            },
            first['defaults'],
        )
        self.assertEqual(
            [
                {
                    'type': 'ssh-key-sha256',
                    'value': 'test-signer',
                }
            ],
            first['verification']['trust_roots'],
        )
        self.assertEqual(
            'experimental',
            first['compatibility']['roms']['unknown']['status'],
        )
        self.assertEqual(
            ['local-unpublished'],
            first['legal']['allowed_output_scopes'],
        )
        self.assertTrue(first['legal']['local_only'])

    def test_native_schema_v2_exposes_complete_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )

            module = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            ).modules[0]

            self.assertEqual(2, module.schema_version)
            self.assertEqual('custom-init', module.lifecycle)
            self.assertFalse(module.defaults.helper_enabled)
            self.assertFalse(module.defaults.pixene_profile_enabled)
            self.assertEqual('supported', module.compatibility.roms['lineageos'].status)
            self.assertEqual('any', module.capabilities.requires.root_provider)
            self.assertEqual(
                'zygisk-next', module.capabilities.requires.zygisk_provider
            )
            self.assertEqual(34, module.capabilities.requires.min_api)
            self.assertEqual(36, module.capabilities.requires.max_api)
            self.assertEqual(('magisk',), module.capabilities.provides.root)
            self.assertEqual(
                ('zygisk-next',), module.capabilities.provides.zygisk
            )
            self.assertEqual('GPL-3.0-or-later', module.legal.license)

    def test_reviewed_experimental_adapter_requires_opt_in_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            original = path.read_text(encoding='UTF-8').replace(
                "status = 'supported'",
                "status = 'experimental'",
                1,
            )
            path.write_text(original, encoding='UTF-8')

            with self.assertRaisesRegex(CatalogError, 'explicit opt-in'):
                load_catalog(directory, registrations=(registration('alpha'),))

            path.write_text(
                original.replace(
                    '[defaults]',
                    "[experimental_opt_in]\n"
                    "required = false\n"
                    "acknowledgement = 'I accept experimental device risk.'\n\n"
                    '[defaults]',
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'policy must be required'):
                load_catalog(directory, registrations=(registration('alpha'),))

            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "required = false\nacknowledgement =",
                    "required = true\nacknowledgement =",
                ),
                encoding='UTF-8',
            )

            module = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            ).modules[0]
            self.assertEqual('experimental', module.status)
            self.assertEqual('alpha', module.adapter)
            self.assertTrue(module.experimental_opt_in.required)
            self.assertEqual(
                'I accept experimental device risk.',
                module.experimental_opt_in.acknowledgement,
            )

    def test_experimental_adapter_cannot_be_default_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8')
                .replace("status = 'supported'", "status = 'experimental'", 1)
                .replace(
                    '[defaults]',
                    "[experimental_opt_in]\n"
                    "required = true\n"
                    "acknowledgement = 'I accept experimental device risk.'\n\n"
                    '[defaults]',
                )
                .replace('helper_enabled = false', 'helper_enabled = true'),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'cannot be enabled by default'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_incompatible_adapter_remains_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8')
                .replace("status = 'supported'", "status = 'incompatible'", 1)
                .replace(
                    'reasons = []',
                    "reasons = [{ code = 'unsupported-target', "
                    "message = 'The target is incompatible.' }]",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(
                CatalogError, 'incompatible modules cannot register an adapter'
            ):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_supported_module_rejects_experimental_opt_in_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    '[defaults]',
                    "[experimental_opt_in]\n"
                    "required = true\n"
                    "acknowledgement = 'Not valid for supported modules.'\n\n"
                    '[defaults]',
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(
                CatalogError, 'valid only for experimental modules'
            ):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_openpgp_verification_requires_primary_and_subkey_roots(self) -> None:
        for root_type in ('openpgp-primary', 'openpgp-subkey'):
            with self.subTest(root_type=root_type):
                with self.assertRaisesRegex(
                    ValueError, 'requires all matching typed trust roots'
                ):
                    VerificationPolicy.model_validate(
                        {
                            'schemes': ['openpgp-signature'],
                            'trust_roots': [
                                {
                                    'type': root_type,
                                    'value': '0' * 40,
                                }
                            ],
                            'digest_required': False,
                            'enforced_by': 'adapter',
                        }
                    )

        policy = VerificationPolicy.model_validate(
            {
                'schemes': ['openpgp-signature'],
                'trust_roots': [
                    {
                        'type': 'openpgp-primary',
                        'value': '0' * 40,
                    },
                    {
                        'type': 'openpgp-subkey',
                        'value': '1' * 40,
                    },
                ],
                'digest_required': False,
                'enforced_by': 'adapter',
            }
        )

        self.assertEqual(
            ('openpgp-primary', 'openpgp-subkey'),
            tuple(root.type for root in policy.trust_roots),
        )

    def test_critical_warning_requires_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    'warnings = []',
                    "warnings = [{ code = 'critical-risk', "
                    "severity = 'critical', message = 'Review required.' }]",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'critical warnings require'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_experimental_rom_requires_structured_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "[compatibility.roms.lineageos]\nstatus = 'supported'",
                    "[compatibility.roms.lineageos]\nstatus = 'experimental'",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'require a reason'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_invalid_api_range_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    'min_api = 34\nmax_api = 36',
                    'min_api = 36\nmax_api = 34',
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'min_api cannot exceed'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_shared_output_requires_permission_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_v2_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8')
                .replace('local_only = true', 'local_only = false')
                .replace(
                    "allowed_output_scopes = ['local-unpublished']",
                    "allowed_output_scopes = ['shared']",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'permission record'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_unknown_schema_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    'schema_version = 1', 'schema_version = 3'
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'unsupported schema_version'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_text_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            catalog = load_catalog(
                directory,
                registrations=(registration('alpha'),),
            )

            self.assertEqual(
                'ID\tSTATUS\tDEFAULT\tARTIFACT KINDS\n'
                'alpha\tsupported\tno\tnative-image-module-zip\n',
                catalog.as_text(),
            )

    def test_missing_supported_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Missing supported'):
                load_catalog(
                    directory,
                    registrations=(registration('alpha'), registration('zeta')),
                )

    def test_renamed_legacy_adapter_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'renamed.toml', id='renamed', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'must match its adapter'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_duplicate_adapter_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            self.write_manifest(
                directory, 'zeta.toml', id='zeta', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Duplicate module adapter'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_duplicate_internal_registration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )

            with self.assertRaisesRegex(CatalogError, 'Duplicate internal adapter'):
                load_catalog(
                    directory,
                    registrations=(registration('alpha'), registration('alpha')),
                )

    def test_strict_scalar_validation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    'default_enabled = false',
                    "default_enabled = 'false'",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_blank_signer_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "trusted_signers = ['test-signer']",
                    "trusted_signers = ['   ']",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_unknown_must_be_sole_compatibility_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "rom_families = ['unknown']",
                    "rom_families = ['unknown', 'lineageos']",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'Invalid module manifest'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_verification_expectation_must_match_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            self.write_manifest(
                directory, 'alpha.toml', id='alpha', adapter='alpha'
            )
            path = directory / 'alpha.toml'
            path.write_text(
                path.read_text(encoding='UTF-8').replace(
                    "trusted_signers = ['test-signer']",
                    "trusted_signers = ['different-signer']",
                ),
                encoding='UTF-8',
            )

            with self.assertRaisesRegex(CatalogError, 'verification expectation'):
                load_catalog(directory, registrations=(registration('alpha'),))

    def test_standalone_catalog_does_not_import_adapter_modules(self) -> None:
        code = """
import sys
from lib.modules.catalog import load_catalog

load_catalog()
loaded = sorted(
    name for name in sys.modules
    if name in {
        'lib.modules.alterinstaller',
        'lib.modules.bcr',
        'lib.modules.custota',
        'lib.modules.msd',
        'lib.modules.oemunlockonboot',
    }
)
if loaded:
    raise SystemExit(f'Adapter modules imported during listing: {loaded}')
"""
        repository_root = Path(__file__).resolve().parents[1]
        subprocess.run([sys.executable, '-c', code], check=True, cwd=repository_root)


if __name__ == '__main__':
    unittest.main()
