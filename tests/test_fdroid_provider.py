# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import io
import json
from contextlib import ExitStack
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from lib.modules.catalog import load_catalog
from lib.modules import cli as module_cli
from lib.modules.fdroid_privileged_extension import (
    FDroidPrivilegedExtensionModule,
)
from lib.modules.locks import (
    ApkIdentity,
    LockError,
    cache_path,
    load_canonical_lock,
)
from lib.modules.providers import get_lock_update_provider
from lib.modules.providers import fdroid
from lib.modules.registry import locked_adapter_factories
from lib.modules.verified import (
    construct_locked_adapters,
    open_verified_selection,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, url: str, content_length: int | None = None):
        super().__init__(data)
        self._url = url
        self.headers = {
            'Content-Encoding': 'identity',
            'Content-Length': str(len(data) if content_length is None else content_length),
        }

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def zip_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


class FDroidProviderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = fdroid.FDROID_X509_CERT_SHA256
        self.permission_xml = b'''<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <privapp-permissions package="org.fdroid.fdroid.privileged">
        <permission name="android.permission.DELETE_PACKAGES"/>
        <permission name="android.permission.INSTALL_PACKAGES"/>
    </privapp-permissions>
</permissions>
'''
        self.client = b'client-apk-fixture'
        self.client_source = b'client-source-fixture'
        self.fpe_apk = b'fpe-apk-fixture'
        self.fpe_source = b'fpe-source-fixture'
        self.ota = zip_bytes({
            'META-INF/': b'',
            'META-INF/com/': b'',
            'META-INF/com/google/': b'',
            'META-INF/com/google/android/': b'',
            'META-INF/com/google/android/update-binary': b'never execute me',
            'permissions_org.fdroid.fdroid.privileged.xml': self.permission_xml,
            'F-Droid.apk': b'unused container client',
            '80-fdroid.sh': b'never execute me either',
            'F-DroidPrivilegedExtension.apk': self.fpe_apk,
        })

        self.client_name = f'/{fdroid.CLIENT_PACKAGE}_{fdroid.CLIENT_VERSION_CODE}.apk'
        self.client_source_name = (
            f'/{fdroid.CLIENT_PACKAGE}_{fdroid.CLIENT_VERSION_CODE}_src.tar.gz'
        )
        self.ota_name = f'/{fdroid.FPE_OTA_PACKAGE}_{fdroid.FPE_VERSION_CODE}.zip'
        self.fpe_name = f'/{fdroid.FPE_PACKAGE}_{fdroid.FPE_VERSION_CODE}.apk'
        self.fpe_source_name = (
            f'/{fdroid.FPE_PACKAGE}_{fdroid.FPE_VERSION_CODE}_src.tar.gz'
        )
        self.index = {
            'packages': {
                fdroid.CLIENT_PACKAGE: self._package(
                    fdroid.CLIENT_VERSION_NAME,
                    fdroid.CLIENT_VERSION_CODE,
                    self.client_name,
                    self.client,
                    source_name=self.client_source_name,
                    source=self.client_source,
                ),
                fdroid.FPE_OTA_PACKAGE: self._package(
                    fdroid.FPE_OTA_VERSION_NAME,
                    fdroid.FPE_VERSION_CODE,
                    self.ota_name,
                    self.ota,
                    signer=False,
                ),
                fdroid.FPE_PACKAGE: self._package(
                    fdroid.FPE_VERSION_NAME,
                    fdroid.FPE_VERSION_CODE,
                    self.fpe_name,
                    self.fpe_apk,
                    source_name=self.fpe_source_name,
                    source=self.fpe_source,
                ),
            },
        }
        self.index_bytes = json.dumps(self.index, sort_keys=True).encode()
        self.entry = {
            'timestamp': 1,
            'version': 30000,
            'maxAge': 14,
            'index': {
                'name': '/index-v2.json',
                'sha256': sha256(self.index_bytes),
                'size': len(self.index_bytes),
                'numPackages': 3,
            },
            'diffs': {},
        }
        self.entry_bytes = json.dumps(self.entry, sort_keys=True).encode()

    def _package(
        self,
        version_name: str,
        version_code: int,
        filename: str,
        data: bytes,
        *,
        source_name: str | None = None,
        source: bytes | None = None,
        signer: bool = True,
    ) -> dict[str, object]:
        manifest: dict[str, object] = {
            'versionName': version_name,
            'versionCode': version_code,
        }
        metadata: dict[str, object] = {}
        if signer:
            metadata['preferredSigner'] = self.signer
            manifest['signer'] = {'sha256': [self.signer]}
        record: dict[str, object] = {
            'file': {'name': filename, 'size': len(data), 'sha256': sha256(data)},
            'manifest': manifest,
        }
        if source_name is not None and source is not None:
            record['src'] = {
                'name': source_name,
                'size': len(source),
                'sha256': sha256(source),
            }
        return {'metadata': metadata, 'versions': {sha256(data): record}}

    def _fetcher(self, mapping: dict[str, bytes]):
        def fetch(
            url: str,
            destination: Path,
            *,
            label: str,
            max_bytes: int,
            expected_size: int | None = None,
            expected_sha256: str | None = None,
        ) -> None:
            del label
            data = mapping[url]
            if len(data) > max_bytes:
                raise LockError('fixture exceeds limit')
            if expected_size is not None and len(data) != expected_size:
                raise LockError('fixture size mismatch')
            if expected_sha256 is not None and sha256(data) != expected_sha256:
                raise LockError('fixture digest mismatch')
            destination.write_bytes(data)

        return fetch

    def _identity(self, path: Path, package: str, version: int, signer: str):
        del path
        return ApkIdentity(
            package_name=package,
            version_code=version,
            signer_sha256=signer,
        )

    def _provider_patches(self, *, include_apk_identity: bool = True):
        patches = (
            mock.patch.object(fdroid, 'CLIENT_APK_SIZE', len(self.client)),
            mock.patch.object(fdroid, 'CLIENT_APK_SHA256', sha256(self.client)),
            mock.patch.object(fdroid, 'CLIENT_SOURCE_SIZE', len(self.client_source)),
            mock.patch.object(fdroid, 'CLIENT_SOURCE_SHA256', sha256(self.client_source)),
            mock.patch.object(fdroid, 'FPE_OTA_SIZE', len(self.ota)),
            mock.patch.object(fdroid, 'FPE_OTA_SHA256', sha256(self.ota)),
            mock.patch.object(fdroid, 'FPE_APK_SIZE', len(self.fpe_apk)),
            mock.patch.object(fdroid, 'FPE_APK_SHA256', sha256(self.fpe_apk)),
            mock.patch.object(fdroid, 'FPE_SOURCE_SIZE', len(self.fpe_source)),
            mock.patch.object(fdroid, 'FPE_SOURCE_SHA256', sha256(self.fpe_source)),
            mock.patch.object(fdroid, 'FPE_PERMISSION_SHA256', sha256(self.permission_xml)),
            mock.patch.object(fdroid, '_verify_entry_jar', return_value=self.entry_bytes),
            mock.patch.object(fdroid, '_verify_openpgp'),
        )
        if include_apk_identity:
            patches += (mock.patch.object(
                fdroid, '_apk_identity', side_effect=self._identity
            ),)
        return patches

    def _artifact_mapping(self) -> dict[str, bytes]:
        return {
            fdroid.ENTRY_JAR_URL: b'fixture-entry-jar',
            fdroid.ENTRY_JSON_URL: self.entry_bytes,
            fdroid.ENTRY_SIGNATURE_URL: b'fixture-signature',
            f'{fdroid.REPOSITORY_URL}index-v2.json': self.index_bytes,
            f'{fdroid.REPOSITORY_ORIGIN}/repo{self.client_name}': self.client,
            f'{fdroid.REPOSITORY_ORIGIN}/repo{self.client_source_name}': (
                self.client_source
            ),
            f'{fdroid.REPOSITORY_ORIGIN}/repo{self.ota_name}': self.ota,
            f'{fdroid.REPOSITORY_ORIGIN}/repo{self.fpe_source_name}': self.fpe_source,
        }

    def _generate_lock(self, output: Path):
        with ExitStack() as stack:
            for patcher in self._provider_patches():
                stack.enter_context(patcher)
            return fdroid.update_fdroid_lock(
                output=output,
                client_version_code=fdroid.CLIENT_VERSION_CODE,
                fpe_ota_version_code=fdroid.FPE_VERSION_CODE,
                fetcher=self._fetcher(self._artifact_mapping()),
            )

    def test_static_registry_never_imports_unknown_module(self) -> None:
        self.assertIs(fdroid.update_fdroid_lock, get_lock_update_provider(fdroid.MODULE_ID))
        self.assertIsNone(get_lock_update_provider('../../untrusted'))

    def test_cli_rejects_positional_role_ambiguity_before_provider_call(self) -> None:
        provider = mock.Mock()
        args = SimpleNamespace(
            module=fdroid.MODULE_ID,
            output=Path('unused.lock.json'),
            version_code=[fdroid.CLIENT_VERSION_CODE, fdroid.FPE_VERSION_CODE],
            client_version_code=fdroid.CLIENT_VERSION_CODE,
            fpe_ota_version_code=fdroid.FPE_VERSION_CODE,
        )
        with (
            mock.patch.object(
                module_cli, 'get_lock_update_provider', return_value=provider
            ),
            self.assertRaisesRegex(LockError, 'requires named'),
        ):
            module_cli._update_lock(args)
        provider.assert_not_called()

    def test_cli_requires_both_named_selectors_and_explicit_output(self) -> None:
        provider = mock.Mock()
        cases = (
            SimpleNamespace(
                module=fdroid.MODULE_ID,
                output=None,
                version_code=None,
                client_version_code=fdroid.CLIENT_VERSION_CODE,
                fpe_ota_version_code=fdroid.FPE_VERSION_CODE,
            ),
            SimpleNamespace(
                module=fdroid.MODULE_ID,
                output=Path('unused.lock.json'),
                version_code=None,
                client_version_code=fdroid.CLIENT_VERSION_CODE,
                fpe_ota_version_code=None,
            ),
        )
        for args in cases:
            with (
                self.subTest(args=args),
                mock.patch.object(
                    module_cli, 'get_lock_update_provider', return_value=provider
                ),
                self.assertRaises(LockError),
            ):
                module_cli._update_lock(args)
        provider.assert_not_called()

    def test_strict_json_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(LockError, 'strict JSON'):
            fdroid._strict_json(b'{"packages": {}, "packages": {}}', label='index')

    def test_strict_json_rejects_excessive_nesting(self) -> None:
        data = b'[' * 2000 + b'0' + b']' * 2000
        with self.assertRaises(LockError):
            fdroid._strict_json(data, label='index')

    def test_checked_in_openpgp_asset_and_fingerprints_are_exact(self) -> None:
        key_data = fdroid.TRUST_KEY_PATH.read_bytes()
        self.assertEqual(fdroid.TRUST_KEY_SHA256, sha256(key_data))
        self.assertEqual(
            '37D2C98789D8311948394E3E41E7044E1DBA2E89',
            fdroid.FDROID_OPENPGP_PRIMARY,
        )
        self.assertEqual(
            '802A9799016112346E1FEFF47A029E54DD5DCE7A',
            fdroid.FDROID_OPENPGP_SIGNING_SUBKEY,
        )

    def test_expired_key_status_fails_even_when_command_exit_was_zero(self) -> None:
        statuses = fdroid._gpg_status_lines(
            b'[GNUPG:] GOODSIG 7A029E54DD5DCE7A F-Droid\n'
            b'[GNUPG:] EXPKEYSIG 7A029E54DD5DCE7A F-Droid\n'
            b'[GNUPG:] VALIDSIG 802A9799016112346E1FEFF47A029E54DD5DCE7A '
            b'0 0 0 4 0 1 10 00 37D2C98789D8311948394E3E41E7044E1DBA2E89\n'
            b'[GNUPG:] KEYEXPIRED 1556112994\n'
        )
        with self.assertRaisesRegex(LockError, 'EXPKEYSIG, KEYEXPIRED'):
            fdroid._reject_unsafe_gpg_status(statuses)

    def test_openpgp_valid_signature_requires_exact_primary_and_subkey(self) -> None:
        imported = SimpleNamespace(
            returncode=0,
            stdout=(
                b'[GNUPG:] IMPORT_OK 1 '
                + fdroid.FDROID_OPENPGP_PRIMARY.encode()
                + b'\n'
            ),
            stderr=b'',
        )
        wrong_primary = b'0' * 40
        verified = SimpleNamespace(
            returncode=0,
            stdout=(
                b'[GNUPG:] GOODSIG 7A029E54DD5DCE7A F-Droid\n'
                b'[GNUPG:] VALIDSIG '
                + fdroid.FDROID_OPENPGP_SIGNING_SUBKEY.encode()
                + b' 0 0 0 4 0 1 10 00 '
                + wrong_primary
                + b'\n'
            ),
            stderr=b'',
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            signature = root / 'entry.json.asc'
            data = root / 'entry.json'
            home = root / 'gnupg'
            signature.write_bytes(b'signature')
            data.write_bytes(b'{}')
            home.mkdir(mode=0o700)
            with (
                mock.patch.object(
                    fdroid, '_run_tool', side_effect=(imported, verified)
                ),
                self.assertRaisesRegex(LockError, 'primary key or signing subkey'),
            ):
                fdroid._verify_openpgp(signature, data, home)

    def test_entry_jar_rejects_unpinned_signer_even_when_jarsigner_succeeds(self) -> None:
        inspection = SimpleNamespace(
            members=tuple(
                SimpleNamespace(name=name) for name in fdroid.ENTRY_JAR_LAYOUT
            )
        )
        tool_results = (
            SimpleNamespace(returncode=0, stdout=b'jar verified\n', stderr=b''),
            SimpleNamespace(
                returncode=0,
                stdout=(
                    b'-----BEGIN CERTIFICATE-----\n'
                    b'fixture\n'
                    b'-----END CERTIFICATE-----\n'
                ),
                stderr=b'',
            ),
            SimpleNamespace(returncode=0, stdout=b'unpinned DER', stderr=b''),
        )
        with (
            mock.patch.object(fdroid, 'inspect_zip', return_value=inspection),
            mock.patch.object(
                fdroid,
                'read_allowlisted_member',
                return_value=b'signature block',
            ),
            mock.patch.object(fdroid, '_run_tool', side_effect=tool_results),
            self.assertRaisesRegex(LockError, 'certificate is not pinned'),
        ):
            fdroid._verify_entry_jar(Path('entry.jar'))

    def test_bounded_fetch_rejects_stream_over_limit_and_leaves_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / 'metadata'
            response = FakeResponse(b'abcd', fdroid.ENTRY_JSON_URL)
            opener = mock.Mock()
            opener.open.return_value = response
            with mock.patch.object(fdroid, 'build_opener', return_value=opener):
                with self.assertRaisesRegex(LockError, 'byte limit'):
                    fdroid._fetch_https(
                        fdroid.ENTRY_JSON_URL,
                        destination,
                        label='entry.json',
                        max_bytes=3,
                    )
            self.assertFalse(destination.exists())
            self.assertFalse((destination.parent / '.metadata.download').exists())

    def test_fetch_rejects_cross_origin_final_url_and_cleans_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / 'metadata'
            response = FakeResponse(b'entry', 'https://attacker.invalid/entry')
            opener = mock.Mock()
            opener.open.return_value = response
            with (
                mock.patch.object(fdroid, 'build_opener', return_value=opener),
                self.assertRaisesRegex(LockError, 'outside the pinned origin'),
            ):
                fdroid._fetch_https(
                    fdroid.ENTRY_JSON_URL,
                    destination,
                    label='entry.json',
                    max_bytes=fdroid.ENTRY_MAX_BYTES,
                )
            self.assertFalse(destination.exists())
            self.assertFalse((destination.parent / '.metadata.download').exists())

    def test_signed_index_cannot_substitute_another_apk_signer(self) -> None:
        other = 'ab' * 32
        package = {'metadata': {'preferredSigner': other}}
        record = {'manifest': {'signer': {'sha256': [other]}}}
        with self.assertRaisesRegex(LockError, 'not the pinned F-Droid signer'):
            fdroid._index_signer(package, record)

    def test_permission_xml_rejects_entities_text_and_extra_attributes(self) -> None:
        variants = (
            self.permission_xml.replace(
                b'<permissions>', b'<permissions>&amp;'
            ),
            self.permission_xml.replace(
                b'<permissions>', b'<permissions extra="true">'
            ),
            self.permission_xml.replace(
                b'<permission name="android.permission.DELETE_PACKAGES"/>',
                b'<permission name="android.permission.DELETE_PACKAGES">'
                b'unexpected</permission>',
            ),
            self.permission_xml.replace(
                b'<privapp-permissions ',
                b'<privapp-permissions>unexpected</privapp-permissions>'
                b'<privapp-permissions ',
            ),
        )
        for data in variants:
            with self.subTest(data=data), self.assertRaises(LockError):
                fdroid._validate_permission_xml(data)

    def test_full_fixture_generates_canonical_lock_with_roles_and_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / 'fdroid.lock.json'
            with mock.patch.object(fdroid.subprocess, 'run') as arbitrary_run:
                lock = self._generate_lock(output)
            arbitrary_run.assert_not_called()

            loaded, _ = load_canonical_lock(output)
            self.assertEqual(lock, loaded)
            artifacts = {artifact.id: artifact for artifact in lock.modules[0].artifacts}
            self.assertEqual(
                (
                    'fdroid-client-apk',
                    'fdroid-client-source',
                    'fdroid-privileged-extension-ota',
                    'fdroid-privileged-extension-source',
                ),
                tuple(artifacts),
            )
            self.assertEqual(
                'fdroid-client-source',
                artifacts['fdroid-client-apk'].source.corresponding_source_artifact,
            )
            self.assertEqual(
                'corresponding-source', artifacts['fdroid-client-source'].role
            )
            self.assertTrue(
                artifacts['fdroid-client-apk'].legal.source_offer_required
            )
            self.assertEqual(
                'fdroid-privileged-extension-source',
                artifacts[
                    'fdroid-privileged-extension-ota'
                ].source.corresponding_source_artifact,
            )
            self.assertEqual(
                'corresponding-source',
                artifacts['fdroid-privileged-extension-source'].role,
            )
            self.assertEqual(
                {('local-unpublished',)},
                {
                    artifact.legal.allowed_output_scopes
                    for artifact in artifacts.values()
                },
            )
            self.assertEqual(
                (fdroid.FPE_APK_MEMBER, fdroid.FPE_PERMISSION_MEMBER),
                artifacts[
                    'fdroid-privileged-extension-ota'
                ].archive.allowlisted_members,
            )
            self.assertIn(
                'openpgp-primary',
                artifacts[
                    'fdroid-privileged-extension-ota'
                ].source_verification.signature_types,
            )

    def test_provider_lock_opens_verified_context_and_static_factory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            lock_path = root / 'fdroid.lock.json'
            lock = self._generate_lock(lock_path)
            lock_sha256 = sha256(lock_path.read_bytes())
            cache = root / 'cache'
            data_by_id = {
                'fdroid-client-apk': self.client,
                'fdroid-client-source': self.client_source,
                'fdroid-privileged-extension-ota': self.ota,
                'fdroid-privileged-extension-source': self.fpe_source,
            }
            for artifact in lock.modules[0].artifacts:
                path = cache_path(cache, artifact.sha256)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data_by_id[artifact.id])
                path.chmod(0o444)

            profile = root / 'lineage-profile.toml'
            profile.write_text(
                f"""schema_version = 1
id = 'fdroid-provider-integration'
rom_family = 'lineageos'
root_mode = 'rootless'
abi = 'arm64-v8a'
api_level = 35
output_scope = 'local-unpublished'
enabled_modules = ['fdroid-privileged-extension']

[capabilities]
root_providers = []
zygisk_providers = []
selective_signature_spoofing = false
product_priv_app = false
custom_init_selinux = false

[[experimental_acknowledgements]]
module = 'fdroid-privileged-extension'
lock_sha256 = '{lock_sha256}'
output_scope = 'local-unpublished'
acknowledgement = 'I accept the F-Droid privileged-extension experimental policy for this exact artifact lock and output scope.'
""",
                encoding='UTF-8',
            )

            with mock.patch(
                'lib.modules.verified.verify_apk_identity'
            ) as verify_apk:
                with open_verified_selection(
                    load_catalog(),
                    lock_path,
                    profile,
                    cache,
                ) as selection:
                    self.assertEqual(
                        tuple(data_by_id),
                        tuple(
                            artifact.id
                            for artifact in selection.contexts[0].artifacts
                        ),
                    )
                    adapters = construct_locked_adapters(
                        selection,
                        locked_adapter_factories(),
                    )
                    self.assertEqual('fdroid-privileged-extension', adapters[0][0])
                    self.assertIsInstance(
                        adapters[0][1], FDroidPrivilegedExtensionModule
                    )
            self.assertEqual(2, verify_apk.call_count)

    def test_embedded_entry_mismatch_never_writes_output(self) -> None:
        mapping = {
            fdroid.ENTRY_JAR_URL: b'fixture-entry-jar',
            fdroid.ENTRY_JSON_URL: self.entry_bytes,
            fdroid.ENTRY_SIGNATURE_URL: b'fixture-signature',
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / 'fdroid.lock.json'
            with mock.patch.object(fdroid, '_verify_entry_jar', return_value=b'other'):
                with self.assertRaisesRegex(LockError, 'embedded and detached'):
                    fdroid.update_fdroid_lock(
                        output=output,
                        client_version_code=fdroid.CLIENT_VERSION_CODE,
                        fpe_ota_version_code=fdroid.FPE_VERSION_CODE,
                        fetcher=self._fetcher(mapping),
                    )
            self.assertFalse(output.exists())

    def test_late_verification_failure_preserves_existing_output_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / 'fdroid.lock.json'
            previous = b'previous reviewed lock\n'
            output.write_bytes(previous)
            with ExitStack() as stack:
                for patcher in self._provider_patches(include_apk_identity=False):
                    stack.enter_context(patcher)
                stack.enter_context(mock.patch.object(
                    fdroid,
                    '_apk_identity',
                    side_effect=LockError('late APK verification failure'),
                ))
                with self.assertRaisesRegex(LockError, 'late APK verification'):
                    fdroid.update_fdroid_lock(
                        output=output,
                        client_version_code=fdroid.CLIENT_VERSION_CODE,
                        fpe_ota_version_code=fdroid.FPE_VERSION_CODE,
                        fetcher=self._fetcher(self._artifact_mapping()),
                    )
            self.assertEqual(previous, output.read_bytes())
            self.assertEqual([], list(output.parent.glob('.fdroid.lock.json.*.tmp')))

    def test_unreviewed_selector_fails_before_fetch(self) -> None:
        fetcher = mock.Mock()
        with self.assertRaisesRegex(LockError, 'unsupported reviewed'):
            fdroid.update_fdroid_lock(
                output=Path('unused'),
                client_version_code=1,
                fpe_ota_version_code=fdroid.FPE_VERSION_CODE,
                fetcher=fetcher,
            )
        fetcher.assert_not_called()


if __name__ == '__main__':
    unittest.main()
