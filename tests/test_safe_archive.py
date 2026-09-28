# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import io
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from lib.modules.archive import (
    ArchiveError,
    ArchiveLimits,
    inspect_zip,
    read_allowlisted_member,
)
from lib.modules.locks import (
    ArchiveMember,
    ArchivePolicy,
    ArtifactLock,
    ArtifactLockFile,
    ModuleLock,
    cache_path,
    verify_locked_artifacts,
)


def write_zip(
    path: Path,
    entries: list[tuple[str | zipfile.ZipInfo, bytes]],
    *,
    compression: int = zipfile.ZIP_STORED,
) -> None:
    with zipfile.ZipFile(path, 'w', compression=compression) as archive:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            for name, data in entries:
                archive.writestr(name, data)


def typed_info(name: str, file_type: int, permissions: int = 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (file_type | permissions) << 16
    return info


def replace_filename_bytes(path: Path, old: bytes, new: bytes) -> None:
    if len(old) != len(new):
        raise ValueError('replacement ZIP filename must have the same encoded length')
    content = path.read_bytes()
    if content.count(old) != 2:
        raise AssertionError('expected filename once in each ZIP header')
    path.write_bytes(content.replace(old, new))


def set_encrypted_flag(path: Path) -> None:
    content = bytearray(path.read_bytes())
    for signature, flag_offset in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
        position = content.find(signature)
        if position < 0:
            raise AssertionError('missing ZIP header')
        flags = struct.unpack_from('<H', content, position + flag_offset)[0]
        struct.pack_into('<H', content, position + flag_offset, flags | 0x1)
    path.write_bytes(content)


def corrupt_first_stored_member(path: Path) -> None:
    content = bytearray(path.read_bytes())
    header = content.find(b'PK\x03\x04')
    if header < 0:
        raise AssertionError('missing local ZIP header')
    name_length, extra_length = struct.unpack_from('<HH', content, header + 26)
    data_offset = header + 30 + name_length + extra_length
    content[data_offset] ^= 0xff
    path.write_bytes(content)


def write_empty_name_zip(path: Path) -> None:
    local = struct.pack(
        '<4s5H3I2H',
        b'PK\x03\x04', 20, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    )
    central = struct.pack(
        '<4s6H3I5H2I',
        b'PK\x01\x02', 20, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    )
    end = struct.pack(
        '<4s4H2IH',
        b'PK\x05\x06', 0, 0, 1, 1, len(central), len(local), 0,
    )
    path.write_bytes(local + central + end)


def write_data_descriptor_zip(path: Path) -> None:
    class NonSeekable(io.BytesIO):
        def seekable(self) -> bool:
            return False

        def seek(self, *args, **kwargs):
            raise io.UnsupportedOperation

    output = NonSeekable()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('payload', b'data')
    path.write_bytes(output.getvalue())


def corrupt_data_descriptor(path: Path) -> None:
    content = bytearray(path.read_bytes())
    descriptor = content.find(b'PK\x07\x08')
    if descriptor < 0:
        raise AssertionError('missing ZIP data descriptor')
    content[descriptor + 4] ^= 0xff
    path.write_bytes(content)


class SafeArchiveTest(unittest.TestCase):
    def make_path(self, directory: str, name: str = 'archive.zip') -> Path:
        return Path(directory) / name

    def assert_rejected(
        self,
        path: Path,
        pattern: str | None = None,
        *,
        limits: ArchiveLimits = ArchiveLimits(),
        allowlisted_members: tuple[str, ...] = (),
    ) -> None:
        context = (
            self.assertRaisesRegex(ArchiveError, pattern)
            if pattern is not None
            else self.assertRaises(ArchiveError)
        )
        with context:
            inspect_zip(
                path,
                limits=limits,
                allowlisted_members=allowlisted_members,
            )

    def test_safe_archive_is_streamed_and_member_is_read_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload/file.apk', b'apk'), ('ignored.txt', b'x')])

            result = inspect_zip(path, allowlisted_members=('payload/file.apk',))

            self.assertEqual(4, result.streamed_bytes)
            self.assertEqual(
                b'apk',
                read_allowlisted_member(
                    path,
                    'payload/file.apk',
                    allowlisted_members=('payload/file.apk',),
                ),
            )

    def test_rejects_absolute_drive_backslash_and_unsafe_components(self) -> None:
        unsafe_names = (
            '/absolute',
            'C:/drive',
            'z:file',
            r'dir\file',
            '.',
            '..',
            './file',
            'dir/../file',
            'dir/./file',
            'dir//file',
            'dir//',
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, name in enumerate(unsafe_names):
                with self.subTest(name=name):
                    path = self.make_path(directory, f'{index}.zip')
                    write_zip(path, [(name, b'x')])
                    self.assert_rejected(path, 'unsafe|absolute|backslash')

    def test_rejects_nul_and_control_characters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for index, replacement in enumerate((b'a\x00b', b'a\x01b', b'a\x1fb', b'a\x7fb')):
                with self.subTest(replacement=replacement):
                    path = self.make_path(directory, f'{index}.zip')
                    write_zip(path, [('aXb', b'x')])
                    replace_filename_bytes(path, b'aXb', replacement)
                    self.assert_rejected(path, 'control character')

            unicode_control = self.make_path(directory, 'unicode-control.zip')
            write_zip(unicode_control, [('a\u0085b', b'x')])
            self.assert_rejected(unicode_control, 'control character')

    def test_rejects_empty_member_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_empty_name_zip(path)
            self.assert_rejected(path, 'empty name')

    def test_rejects_duplicate_raw_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('same', b'one'), ('same', b'two')])
            self.assert_rejected(path, 'duplicate member name')

    def test_rejects_duplicate_nfc_normalized_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('cafe\u0301', b'one'), ('caf\u00e9', b'two')])
            self.assert_rejected(path, 'duplicate normalized name')

    def test_rejects_file_directory_namespace_collision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('same', b'file'), ('same/', b'')])
            self.assert_rejected(path, 'duplicate normalized name')

    def test_rejects_symlink_device_and_fifo_entries(self) -> None:
        hostile_types = (
            stat.S_IFLNK,
            stat.S_IFCHR,
            stat.S_IFBLK,
            stat.S_IFIFO,
            stat.S_IFSOCK,
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, file_type in enumerate(hostile_types):
                with self.subTest(file_type=file_type):
                    path = self.make_path(directory, f'{index}.zip')
                    write_zip(path, [(typed_info('hostile', file_type), b'target')])
                    self.assert_rejected(path, 'not a regular file or directory')

    def test_rejects_file_directory_type_conflicts(self) -> None:
        cases = (
            typed_info('claimed-directory/', stat.S_IFREG),
            typed_info('claimed-file', stat.S_IFDIR),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, info in enumerate(cases):
                with self.subTest(name=info.filename):
                    path = self.make_path(directory, f'{index}.zip')
                    write_zip(path, [(info, b'')])
                    self.assert_rejected(path, 'type conflicts')

    def test_rejects_directory_with_file_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('directory/', b'hidden')])
            self.assert_rejected(path, 'directory contains file data')

    def test_rejects_encrypted_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload', b'data')])
            set_encrypted_flag(path)
            self.assert_rejected(path, 'encrypted')

    def test_rejects_unsupported_compression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload', b'data')], compression=zipfile.ZIP_BZIP2)
            self.assert_rejected(path, 'unsupported compression')

    def test_rejects_excess_member_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('one', b''), ('two', b'')])
            self.assert_rejected(path, 'too many members', limits=ArchiveLimits(max_members=1))

    def test_rejects_excess_member_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload', b'12')])
            self.assert_rejected(path, 'size limit', limits=ArchiveLimits(max_member_size=1))

    def test_rejects_excess_total_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('one', b'12'), ('two', b'34')])
            self.assert_rejected(path, 'total uncompressed size', limits=ArchiveLimits(max_total_size=3))

    def test_rejects_excess_expansion_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload', b'\x00' * 4096)], compression=zipfile.ZIP_DEFLATED)
            self.assert_rejected(path, 'expansion ratio', limits=ArchiveLimits(max_expansion_ratio=2))

    def test_rejects_excess_streamed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('one', b'12'), ('two', b'34')])
            self.assert_rejected(path, 'streamed byte limit', limits=ArchiveLimits(max_streamed_bytes=3))

    def test_rejects_crc_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload', b'data')])
            corrupt_first_stored_member(path)
            self.assert_rejected(path, 'CRC or is truncated')

    def test_rejects_malformed_deflate_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(
                path,
                [('payload', b'data' * 64)],
                compression=zipfile.ZIP_DEFLATED,
            )
            corrupt_first_stored_member(path)
            self.assert_rejected(path, 'CRC or is truncated')

    def test_rejects_mismatched_data_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_data_descriptor_zip(path)
            inspect_zip(path)
            corrupt_data_descriptor(path)
            self.assert_rejected(path, 'data descriptor differs')

    def test_rejects_truncated_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload', b'data')])
            path.write_bytes(path.read_bytes()[:-8])
            self.assert_rejected(path, 'invalid or truncated ZIP')

    def test_rejects_missing_and_duplicate_allowlisted_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = self.make_path(directory, 'missing.zip')
            write_zip(missing, [('other', b'data')])
            self.assert_rejected(
                missing,
                'missing allowlisted members',
                allowlisted_members=('required',),
            )

            duplicate = self.make_path(directory, 'duplicate.zip')
            write_zip(duplicate, [('required', b'one'), ('required', b'two')])
            self.assert_rejected(
                duplicate,
                'duplicate member name',
                allowlisted_members=('required',),
            )

            with self.assertRaisesRegex(ArchiveError, 'must be unique'):
                inspect_zip(missing, allowlisted_members=('required', 'required'))

    def test_allowlist_matching_is_exact_and_nfc_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('dir/payload.apk', b'apk')])

            for member in ('payload.apk', 'dir/PAYLOAD.apk', 'dir/payload'):
                with self.subTest(member=member):
                    self.assert_rejected(
                        path,
                        'missing allowlisted members',
                        allowlisted_members=(member,),
                    )

            with self.assertRaisesRegex(ArchiveError, 'not NFC-normalized'):
                inspect_zip(path, allowlisted_members=('cafe\u0301',))

    def test_read_rejects_non_allowlisted_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('allowed', b'yes'), ('other', b'no')])
            with self.assertRaisesRegex(ArchiveError, 'not allowlisted'):
                read_allowlisted_member(
                    path,
                    'other',
                    allowlisted_members=('allowed',),
                )

    def test_read_rejects_allowlisted_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('allowed/', b'')])
            with self.assertRaisesRegex(ArchiveError, 'not a regular file'):
                read_allowlisted_member(
                    path,
                    'allowed/',
                    allowlisted_members=('allowed/',),
                )

    def test_allowlisted_read_validates_with_one_archive_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('allowed', b'yes'), ('other', b'also checked')])
            with mock.patch(
                'lib.modules.archive.zipfile.ZipFile',
                wraps=zipfile.ZipFile,
            ) as constructor:
                self.assertEqual(
                    b'yes',
                    read_allowlisted_member(
                        path,
                        'allowed',
                        allowlisted_members=('allowed',),
                    ),
                )
            self.assertEqual(1, constructor.call_count)

    def test_inspection_and_read_never_use_zip_extraction_apis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_path(directory)
            write_zip(path, [('payload', b'data')])
            with (
                mock.patch.object(zipfile.ZipFile, 'extract', side_effect=AssertionError),
                mock.patch.object(zipfile.ZipFile, 'extractall', side_effect=AssertionError),
            ):
                inspect_zip(path, allowlisted_members=('payload',))
                self.assertEqual(
                    b'data',
                    read_allowlisted_member(
                        path,
                        'payload',
                        allowlisted_members=('payload',),
                    ),
                )

    def test_archive_scripts_are_data_and_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'installer.zip'
            sentinel = root / 'EXECUTED'
            script = f'#!/bin/sh\ntouch {sentinel}\n'.encode()
            write_zip(
                path,
                [
                    ('customize.sh', script),
                    ('META-INF/com/google/android/update-binary', script),
                    ('payload.apk', b'apk'),
                ],
            )

            inspect_zip(path, allowlisted_members=('payload.apk',))
            self.assertEqual(
                b'apk',
                read_allowlisted_member(
                    path,
                    'payload.apk',
                    allowlisted_members=('payload.apk',),
                ),
            )
            self.assertFalse(sentinel.exists())

    def test_locked_archive_verification_applies_hostile_archive_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.zip'
            write_zip(source, [('../payload', b'data')])
            content = source.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            artifact = ArtifactLock(
                id='hostile-archive',
                kind='zip',
                immutable_url='https://example.invalid/hostile.zip',
                allowed_origins=('https://example.invalid',),
                version='1',
                size=len(content),
                sha256=digest,
                archive=ArchivePolicy(members=(ArchiveMember(
                    name='../payload',
                    size=4,
                    sha256=hashlib.sha256(b'data').hexdigest(),
                ),)),
            )
            lock = ArtifactLockFile(
                schema_version=1,
                modules=(ModuleLock(id='test-module', version='1', artifacts=(artifact,)),),
            )
            cached = cache_path(root / 'cache', digest)
            cached.parent.mkdir(parents=True)
            cached.write_bytes(content)

            with self.assertRaisesRegex(ArchiveError, 'unsafe path component'):
                verify_locked_artifacts(lock, root / 'cache', verify_apks=False)


if __name__ == '__main__':
    unittest.main()
