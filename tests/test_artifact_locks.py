# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.request import Request
import zipfile

from pydantic import ValidationError

from lib.modules.archive import (
    read_allowlisted_member as read_archive_member,
    read_allowlisted_members as read_archive_members,
)
from lib.modules.locks import (
    ApkIdentity,
    ArchiveMember,
    ArchivePolicy,
    _ArtifactRedirectHandler,
    ArtifactLegal,
    ArtifactLock,
    ArtifactLockFile,
    ArtifactSource,
    LockError,
    MAX_LOCK_FILE_BYTES,
    ModuleLock,
    cache_path,
    _download_https,
    fetch_artifact,
    load_canonical_lock,
    load_lock,
    verify_cached_artifact,
    verify_apk_identity,
    verify_locked_artifacts,
    write_lock,
)


def artifact_for(data: bytes = b'locked bytes') -> ArtifactLock:
    return ArtifactLock(
        id='payload',
        kind='other',
        immutable_url='https://downloads.example/releases/v1/payload.bin',
        allowed_origins=('https://downloads.example',),
        version='v1',
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


class ArtifactLockTest(unittest.TestCase):
    def test_canonical_round_trip(self) -> None:
        lock = ArtifactLockFile(
            schema_version=1,
            modules=(ModuleLock(
                id='alpha',
                version='1',
                artifacts=(artifact_for(),),
            ),),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / 'lock.json'
            write_lock(path, lock)
            first = path.read_bytes()
            loaded = load_lock(path)
            write_lock(path, loaded)
            self.assertEqual(first, path.read_bytes())
            self.assertTrue(first.endswith(b'\n'))
            self.assertEqual(lock, loaded)

    def test_pre_extension_schema_v1_lock_remains_canonical_input(self) -> None:
        lock = ArtifactLockFile(
            schema_version=1,
            modules=(ModuleLock(
                id='alpha',
                version='1',
                artifacts=(artifact_for(),),
            ),),
        )
        legacy = lock._as_legacy_v1_json()
        self.assertIsNotNone(legacy)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / 'lock.json'
            path.write_text(legacy, encoding='UTF-8')

            loaded, digest = load_canonical_lock(path)

            self.assertEqual(lock, loaded)
            self.assertEqual(
                hashlib.sha256(legacy.encode('UTF-8')).hexdigest(),
                digest,
            )

    def test_extra_and_duplicate_ids_fail_closed(self) -> None:
        artifact = artifact_for()
        with self.assertRaises(ValidationError):
            ArtifactLock.model_validate({
                **artifact.model_dump(mode='json'),
                'unexpected': True,
            })
        with self.assertRaises(ValidationError):
            ModuleLock(
                id='alpha',
                version='1',
                artifacts=(artifact, artifact),
            )

    def test_canonical_order_is_required(self) -> None:
        first = artifact_for(b'one').model_copy(update={'id': 'zeta'})
        second = artifact_for(b'two').model_copy(update={'id': 'alpha'})
        with self.assertRaises(ValidationError):
            ModuleLock(
                id='alpha',
                version='1',
                artifacts=(first, second),
            )

    def test_url_and_digest_are_strict(self) -> None:
        artifact = artifact_for()
        for url in (
            'http://example.com/payload',
            'https://user:secret@example.com/payload',
            'https://example.com/payload#fragment',
            'https://example.com/unsafe\npath',
            'https://example.com/unsafe\\path',
            'https://example.com/caf\u00e9',
        ):
            with self.subTest(url=url), self.assertRaises(ValidationError):
                ArtifactLock.model_validate({
                    **artifact.model_dump(), 'immutable_url': url
                })
        with self.assertRaises(ValidationError):
            ArtifactLock.model_validate({
                **artifact.model_dump(),
                'sha256': artifact.sha256.upper(),
            })

        for origin in ('https://127.0.0.1', 'https://localhost'):
            with self.subTest(origin=origin), self.assertRaises(ValidationError):
                ArtifactLock.model_validate({
                    **artifact.model_dump(),
                    'allowed_origins': [origin],
                })
        with self.assertRaises(ValidationError):
            ArtifactLock.model_validate({
                **artifact.model_dump(),
                'allowed_origins': [
                    'https://downloads.example',
                    'https://downloads.example:443',
                ],
            })

    def test_redirect_is_rejected_before_request_creation(self) -> None:
        artifact = artifact_for()
        handler = _ArtifactRedirectHandler(artifact)
        with self.assertRaisesRegex(LockError, 'outside allowed origins'):
            handler.redirect_request(
                Request(artifact.immutable_url),
                None,
                302,
                'Found',
                {},
                'https://other.example/payload',
            )

    def test_download_errors_do_not_expose_raw_urls(self) -> None:
        artifact = artifact_for().model_copy(update={
            'immutable_url': (
                'https://downloads.example/releases/v1/payload.bin?token=secret'
            ),
        })
        opener = mock.Mock()
        opener.open.side_effect = OSError(artifact.immutable_url)
        with mock.patch('lib.modules.locks.build_opener', return_value=opener):
            with self.assertRaisesRegex(LockError, 'artifact download failed: payload') as raised:
                _download_https(artifact, io.BytesIO())
        self.assertNotIn('token=secret', str(raised.exception))

    def test_apk_identity_is_required_for_apk_only(self) -> None:
        artifact = artifact_for()
        with self.assertRaises(ValidationError):
            ArtifactLock.model_validate({
                **artifact.model_dump(),
                'kind': 'apk',
            })
        apk = ApkIdentity(
            package_name='org.example.app',
            version_code=1,
            signer_sha256='AA:' * 31 + 'AA',
        )
        with self.assertRaises(ValidationError):
            ArtifactLock.model_validate({
                **artifact.model_dump(),
                'apk': apk.model_dump(),
            })

    def test_archive_member_can_lock_nested_apk_identity(self) -> None:
        member = ArchiveMember(
            name='system/app/Example/Example.apk',
            size=17,
            sha256='ab' * 32,
            apk=ApkIdentity(
                package_name='org.example.app',
                version_code=7,
                signer_sha256='cd' * 32,
            ),
        )

        self.assertEqual('org.example.app', member.apk.package_name)
        self.assertEqual(
            member,
            ArchiveMember.model_validate(member.model_dump(mode='json')),
        )

    def test_artifact_legal_source_link_is_explicit_and_version_bound(self) -> None:
        binary = artifact_for().model_copy(update={
            'id': 'client-apk',
            'kind': 'apk',
            'apk': ApkIdentity(
                package_name='org.example.app',
                version_code=7,
                signer_sha256='cd' * 32,
            ),
            'source': ArtifactSource(
                url='https://git.example/org/example',
                revision='v1',
                corresponding_source_artifact='client-source',
            ),
            'legal': ArtifactLegal(
                license='GPL-3.0-or-later',
                source_offer_required=True,
                allowed_output_scopes=('shared', 'published'),
            ),
        })
        source = artifact_for(b'source').model_copy(update={
            'id': 'client-source',
            'kind': 'zip',
            'role': 'corresponding-source',
        })
        # model_copy deliberately skips validation, so bind the expected version.
        source = ArtifactLock.model_validate({
            **source.model_dump(mode='json'),
            'version': 'v1',
        })

        module = ModuleLock(
            id='alpha',
            version='1',
            artifacts=(binary, source),
        )

        self.assertEqual('injection-input', module.artifacts[0].role)
        self.assertEqual('corresponding-source', module.artifacts[1].role)
        self.assertEqual(
            'client-source',
            module.artifacts[0].source.corresponding_source_artifact,
        )

    def test_source_offer_requires_locked_corresponding_source(self) -> None:
        artifact = artifact_for()
        with self.assertRaisesRegex(
            ValidationError, 'require locked corresponding source'
        ):
            ArtifactLock.model_validate({
                **artifact.model_dump(mode='json'),
                'legal': {
                    'license': 'GPL-3.0-or-later',
                    'source_offer_required': True,
                    'allowed_output_scopes': ['published'],
                },
            })

    def test_corresponding_source_link_fails_closed(self) -> None:
        binary = artifact_for().model_copy(update={
            'id': 'client-apk',
            'source': ArtifactSource(
                url='https://git.example/org/example',
                revision='v1',
                corresponding_source_artifact='client-source',
            ),
        })
        source = artifact_for(b'source').model_copy(update={
            'id': 'client-source',
            'version': 'wrong-revision',
            'role': 'corresponding-source',
        })

        with self.assertRaisesRegex(ValidationError, 'references missing'):
            ModuleLock(
                id='alpha',
                version='1',
                artifacts=(binary,),
            )

        with self.assertRaisesRegex(ValidationError, 'version must match'):
            ModuleLock(
                id='alpha',
                version='1',
                artifacts=(binary, source),
            )

        not_source = source.model_copy(update={
            'version': 'v1',
            'role': 'verification-evidence',
        })
        with self.assertRaisesRegex(ValidationError, 'corresponding-source role'):
            ModuleLock(
                id='alpha',
                version='1',
                artifacts=(binary, not_source),
            )

    def test_bounded_fetch_and_cache_reverification(self) -> None:
        data = b'locked bytes'
        artifact = artifact_for(data)

        def downloader(_artifact: ArtifactLock, output: io.BytesIO) -> None:
            output.write(data)

        with tempfile.TemporaryDirectory() as temp_dir:
            cache = Path(temp_dir)
            path = fetch_artifact(artifact, cache, downloader=downloader)
            self.assertEqual(data, path.read_bytes())
            self.assertEqual(path, verify_cached_artifact(artifact, cache))
            path.chmod(0o644)
            path.write_bytes(b'poisoned data')
            with self.assertRaisesRegex(LockError, 'wrong size'):
                verify_cached_artifact(artifact, cache)

    def test_fetch_handles_short_file_writes_without_misaccounting(self) -> None:
        data = b'locked bytes'
        artifact = artifact_for(data)
        real_fdopen = os.fdopen

        class ShortWriter:
            def __init__(self, raw) -> None:
                self.raw = raw

            def __enter__(self):
                self.raw.__enter__()
                return self

            def __exit__(self, *args):
                return self.raw.__exit__(*args)

            def write(self, value) -> int:
                return self.raw.write(value[:2])

            def flush(self) -> None:
                self.raw.flush()

            def fileno(self) -> int:
                return self.raw.fileno()

        def short_fdopen(descriptor, mode, **kwargs):
            opened = real_fdopen(descriptor, mode, **kwargs)
            return ShortWriter(opened) if 'w' in mode else opened

        def downloader(_artifact: ArtifactLock, output: io.BytesIO) -> None:
            output.write(data)

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch(
            'lib.modules.locks.os.fdopen',
            side_effect=short_fdopen,
        ):
            path = fetch_artifact(artifact, Path(temp_dir), downloader=downloader)
            self.assertEqual(data, path.read_bytes())

    def test_cache_directory_symlink_is_rejected_before_download(self) -> None:
        artifact = artifact_for()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cache = root / 'cache'
            outside = root / 'outside'
            cache.mkdir()
            outside.mkdir()
            (cache / 'sha256').symlink_to(outside, target_is_directory=True)
            downloader = mock.Mock()

            with self.assertRaisesRegex(LockError, 'not a real directory'):
                fetch_artifact(artifact, cache, downloader=downloader)
            downloader.assert_not_called()
            self.assertEqual([], list(outside.iterdir()))

    def test_oversized_and_short_downloads_leave_no_object(self) -> None:
        artifact = artifact_for(b'expected')
        cases = (b'expected plus extra', b'short')
        for data in cases:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temp_dir:
                cache = Path(temp_dir)

                def downloader(_artifact: ArtifactLock, output: io.BytesIO) -> None:
                    output.write(data)

                with self.assertRaises(LockError):
                    fetch_artifact(artifact, cache, downloader=downloader)
                self.assertFalse(cache_path(cache, artifact.sha256).exists())

    def test_wrong_digest_leaves_no_object(self) -> None:
        expected = b'expected'
        artifact = artifact_for(expected).model_copy(update={
            'sha256': hashlib.sha256(b'different').hexdigest(),
        })
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = Path(temp_dir)

            def downloader(_artifact: ArtifactLock, output: io.BytesIO) -> None:
                output.write(expected)

            with self.assertRaisesRegex(LockError, 'wrong SHA-256'):
                fetch_artifact(artifact, cache, downloader=downloader)

    def test_invalid_json_lock_is_wrapped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / 'lock.json'
            path.write_text(json.dumps({'schema_version': 1}), encoding='UTF-8')
            with self.assertRaisesRegex(LockError, 'invalid artifact lock'):
                load_lock(path)

    def test_duplicate_json_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / 'lock.json'
            path.write_text(
                '{"schema_version":1,"schema_version":1,"modules":[]}',
                encoding='UTF-8',
            )
            with self.assertRaisesRegex(LockError, 'invalid artifact lock'):
                load_lock(path)

    def test_lock_size_is_bounded_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / 'lock.json'
            with path.open('wb') as output:
                output.truncate(MAX_LOCK_FILE_BYTES + 1)
            with mock.patch(
                'lib.modules.locks.json.loads',
                side_effect=AssertionError('oversized lock was parsed'),
            ) as loads, self.assertRaisesRegex(LockError, 'byte limit'):
                load_lock(path)
            loads.assert_not_called()

    def test_identity_tools_consume_verified_inode_after_cache_replacement(self) -> None:
        data = b'original verified apk bytes'
        signer = 'ab' * 32
        artifact = artifact_for(data).model_copy(update={
            'kind': 'apk',
            'apk': ApkIdentity(
                package_name='org.example.app',
                version_code=7,
                signer_sha256=signer,
            ),
        })
        lock = ArtifactLockFile(
            schema_version=1,
            modules=(ModuleLock(
                id='alpha',
                version='1',
                artifacts=(artifact,),
            ),),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = Path(temp_dir)
            path = cache_path(cache, artifact.sha256)
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            path.chmod(0o444)

            def inspect_identity(fd_path, _expected, *, pass_fds):
                replacement = path.with_suffix('.replacement')
                replacement.write_bytes(b'x' * len(data))
                replacement.chmod(0o444)
                os.replace(replacement, path)
                self.assertEqual((int(fd_path.name),), pass_fds)
                self.assertEqual(data, fd_path.read_bytes())

            with mock.patch(
                'lib.modules.locks.verify_apk_identity',
                side_effect=inspect_identity,
            ):
                self.assertEqual(
                    (path,),
                    verify_locked_artifacts(lock, cache),
                )
            self.assertEqual(b'x' * len(data), path.read_bytes())

    def test_nested_apk_identity_uses_verified_outer_inode_and_anonymous_fd(self) -> None:
        nested_data = b'original nested APK bytes'
        expected_identity = ApkIdentity(
            package_name='org.example.nested',
            version_code=11,
            signer_sha256='ab' * 32,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / 'payload.zip'
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('nested.apk', nested_data)
                archive.writestr('installer.sh', b'never execute')
            archive_data = archive_path.read_bytes()
            artifact = ArtifactLock(
                id='nested-payload',
                kind='zip',
                immutable_url='https://downloads.example/releases/v1/payload.zip',
                allowed_origins=('https://downloads.example',),
                version='v1',
                size=len(archive_data),
                sha256=hashlib.sha256(archive_data).hexdigest(),
                archive=ArchivePolicy(members=(ArchiveMember(
                    name='nested.apk',
                    size=len(nested_data),
                    sha256=hashlib.sha256(nested_data).hexdigest(),
                    apk=expected_identity,
                ),)),
            )
            lock = ArtifactLockFile(
                schema_version=1,
                modules=(ModuleLock(
                    id='alpha',
                    version='1',
                    artifacts=(artifact,),
                ),),
            )
            cache = root / 'cache'
            cached = cache_path(cache, artifact.sha256)
            cached.parent.mkdir(parents=True)
            cached.write_bytes(archive_data)
            cached.chmod(0o444)

            def replace_cache_then_read(path, members, *args, **kwargs):
                replacement = cached.with_suffix('.replacement')
                replacement.write_bytes(b'attacker-controlled replacement')
                replacement.chmod(0o444)
                os.replace(replacement, cached)
                return read_archive_members(path, members, *args, **kwargs)

            def inspect_nested(path, expected, *, pass_fds):
                self.assertEqual(expected_identity, expected)
                self.assertEqual((int(path.name),), pass_fds)
                self.assertEqual(nested_data, path.read_bytes())

            with (
                mock.patch(
                    'lib.modules.locks.read_allowlisted_members',
                    side_effect=replace_cache_then_read,
                ) as read_member,
                mock.patch(
                    'lib.modules.locks.verify_apk_identity',
                    side_effect=inspect_nested,
                ) as verify_identity,
            ):
                self.assertEqual((cached,), verify_locked_artifacts(lock, cache))

            read_member.assert_called_once()
            verify_identity.assert_called_once()
            self.assertEqual(b'attacker-controlled replacement', cached.read_bytes())

    def test_nested_apk_identity_failure_fails_generic_verification(self) -> None:
        nested_data = b'nested APK bytes'
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / 'payload.zip'
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr('nested.apk', nested_data)
            archive_data = archive_path.read_bytes()
            artifact = ArtifactLock(
                id='nested-payload',
                kind='zip',
                immutable_url='https://downloads.example/releases/v1/payload.zip',
                allowed_origins=('https://downloads.example',),
                version='v1',
                size=len(archive_data),
                sha256=hashlib.sha256(archive_data).hexdigest(),
                archive=ArchivePolicy(members=(ArchiveMember(
                    name='nested.apk',
                    size=len(nested_data),
                    sha256=hashlib.sha256(nested_data).hexdigest(),
                    apk=ApkIdentity(
                        package_name='org.example.nested',
                        version_code=11,
                        signer_sha256='ab' * 32,
                    ),
                ),)),
            )
            lock = ArtifactLockFile(
                schema_version=1,
                modules=(ModuleLock(
                    id='alpha',
                    version='1',
                    artifacts=(artifact,),
                ),),
            )
            cache = root / 'cache'
            cached = cache_path(cache, artifact.sha256)
            cached.parent.mkdir(parents=True)
            cached.write_bytes(archive_data)
            cached.chmod(0o444)

            with (
                mock.patch(
                    'lib.modules.locks.verify_apk_identity',
                    side_effect=LockError('required verifier is unavailable: apksigner'),
                ) as verify_identity,
                self.assertRaisesRegex(LockError, 'required verifier is unavailable'),
            ):
                verify_locked_artifacts(lock, cache)
            verify_identity.assert_called_once()

    def test_apk_identity_requires_exact_single_signer_and_numeric_version(self) -> None:
        signer = 'ab' * 32
        expected = ApkIdentity(
            package_name='org.example.app',
            version_code=7,
            signer_sha256=signer,
        )
        with mock.patch(
            'lib.modules.locks._run_identity_command',
            side_effect=[
                f'Signer #1 certificate SHA-256 digest: {signer}\n',
                'org.example.app\n',
                '7\n',
            ],
        ):
            verify_apk_identity(Path('app.apk'), expected)

        with mock.patch(
            'lib.modules.locks._run_identity_command',
            return_value=(
                f'Signer #1 certificate SHA-256 digest: {signer}\n'
                f'Signer #2 certificate SHA-256 digest: {signer}\n'
            ),
        ), self.assertRaisesRegex(LockError, 'single locked signer'):
            verify_apk_identity(Path('app.apk'), expected)

        with mock.patch(
            'lib.modules.locks._run_identity_command',
            side_effect=[
                f'Signer #1 certificate SHA-256 digest: {signer}\n',
                'org.example.app\n',
                '7\n8\n',
            ],
        ), self.assertRaisesRegex(LockError, 'invalid versionCode'):
            verify_apk_identity(Path('app.apk'), expected)


if __name__ == '__main__':
    unittest.main()
