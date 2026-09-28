# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Bounded, non-executing ZIP inspection and allowlisted member reads."""

from collections.abc import Iterable
import dataclasses
import hashlib
import stat
from pathlib import Path
import re
import struct
import unicodedata
import zipfile
import zlib


_DRIVE_PREFIX = re.compile(r'^[A-Za-z]:')
_SAFE_COMPRESSION = frozenset((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))


class ArchiveError(ValueError):
    """An archive is malformed or exceeds the configured safety policy."""


@dataclasses.dataclass(frozen=True)
class ArchiveLimits:
    max_members: int = 4096
    max_member_size: int = 128 * 1024 * 1024
    max_total_size: int = 512 * 1024 * 1024
    max_expansion_ratio: int = 200
    max_streamed_bytes: int = 512 * 1024 * 1024
    max_extra_size: int = 4096
    max_comment_size: int = 4096
    chunk_size: int = 64 * 1024

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f'{field.name} must be a positive integer')


@dataclasses.dataclass(frozen=True)
class InspectedMember:
    name: str
    size: int
    compressed_size: int
    crc32: str
    sha256: str | None


@dataclasses.dataclass(frozen=True)
class InspectionResult:
    members: tuple[InspectedMember, ...]
    streamed_bytes: int

    def as_dict(self) -> dict[str, object]:
        return {
            'members': [dataclasses.asdict(member) for member in self.members],
            'streamed_bytes': self.streamed_bytes,
        }


def _validate_name(name: str) -> str:
    if not name:
        raise ArchiveError('archive member has an empty name')
    if any(unicodedata.category(char) == 'Cc' for char in name):
        raise ArchiveError(f'archive member contains a control character: {name!r}')
    if '\\' in name:
        raise ArchiveError(f'archive member contains a backslash: {name!r}')
    if name.startswith('/') or _DRIVE_PREFIX.match(name):
        raise ArchiveError(f'archive member uses an absolute or drive path: {name!r}')

    path_name = name[:-1] if name.endswith('/') else name
    components = path_name.split('/')
    if not path_name or any(component in ('', '.', '..') for component in components):
        raise ArchiveError(f'archive member has an unsafe path component: {name!r}')
    return unicodedata.normalize('NFC', name)


def _validate_type(info: zipfile.ZipInfo) -> None:
    unix_mode = (info.external_attr >> 16) & 0xffff
    file_type = stat.S_IFMT(unix_mode)
    if file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR):
        raise ArchiveError(f'archive member is not a regular file or directory: {info.filename!r}')
    if info.is_dir() and file_type == stat.S_IFREG:
        raise ArchiveError(f'archive member type conflicts with its name: {info.filename!r}')
    if not info.is_dir() and file_type == stat.S_IFDIR:
        raise ArchiveError(f'archive member type conflicts with its name: {info.filename!r}')


def _validate_infos(
    infos: list[zipfile.ZipInfo],
    allowlisted_members: frozenset[str],
    limits: ArchiveLimits,
) -> dict[str, zipfile.ZipInfo]:
    if len(infos) > limits.max_members:
        raise ArchiveError(
            f'archive has too many members: {len(infos)} > {limits.max_members}'
        )

    raw_names: set[str] = set()
    normalized_names: set[str] = set()
    by_name: dict[str, zipfile.ZipInfo] = {}
    total_size = 0
    path_types: dict[str, bool] = {}

    for info in infos:
        name = info.filename
        normalized = _validate_name(name)
        normalized_path = normalized[:-1] if normalized.endswith('/') else normalized
        if name in raw_names:
            raise ArchiveError(f'archive contains a duplicate member name: {name!r}')
        if normalized_path in normalized_names:
            raise ArchiveError(f'archive contains a duplicate normalized name: {name!r}')
        raw_names.add(name)
        normalized_names.add(normalized_path)
        path_types[normalized_path] = info.is_dir()

        if info.flag_bits & 0x1:
            raise ArchiveError(f'archive member is encrypted: {name!r}')
        if info.compress_type not in _SAFE_COMPRESSION:
            raise ArchiveError(f'archive member uses unsupported compression: {name!r}')
        allowed_flags = 0x800 | 0x08
        if info.compress_type == zipfile.ZIP_DEFLATED:
            allowed_flags |= 0x06
        if info.flag_bits & ~allowed_flags:
            raise ArchiveError(f'archive member uses unsupported ZIP flags: {name!r}')
        _validate_type(info)
        if info.is_dir() and info.file_size != 0:
            raise ArchiveError(f'archive directory contains file data: {name!r}')
        if len(info.extra) > limits.max_extra_size or len(info.comment) > limits.max_comment_size:
            raise ArchiveError(f'archive member metadata exceeds the size limit: {name!r}')

        if info.file_size < 0 or info.compress_size < 0:
            raise ArchiveError(f'archive member has an invalid size: {name!r}')
        if info.file_size > limits.max_member_size:
            raise ArchiveError(f'archive member exceeds the size limit: {name!r}')
        total_size += info.file_size
        if total_size > limits.max_total_size:
            raise ArchiveError('archive exceeds the total uncompressed size limit')
        if info.file_size:
            if info.compress_size == 0:
                raise ArchiveError(f'archive member has an invalid expansion ratio: {name!r}')
            if info.file_size > info.compress_size * limits.max_expansion_ratio:
                raise ArchiveError(f'archive member exceeds the expansion ratio limit: {name!r}')

        by_name[name] = info

    for path_name, is_directory in path_types.items():
        components = path_name.split('/')
        for index in range(1, len(components)):
            prefix = '/'.join(components[:index])
            if prefix in path_types and not path_types[prefix]:
                raise ArchiveError(f'archive contains a file/directory prefix collision: {prefix!r}')

    missing = allowlisted_members - set(by_name)
    if missing:
        raise ArchiveError(f'archive is missing allowlisted members: {", ".join(sorted(missing))}')
    return by_name


def _validate_physical_layout(
    source,
    infos: list[zipfile.ZipInfo],
    central_directory_offset: int,
    limits: ArchiveLimits,
) -> None:
    """Cross-check local headers and compressed byte ranges against the directory."""

    if not infos:
        return
    ordered = sorted(infos, key=lambda info: info.header_offset)
    if ordered[0].header_offset != 0:
        raise ArchiveError('archive contains prepended data')
    ranges: list[tuple[int, int, str]] = []
    for index, info in enumerate(ordered):
        source.seek(info.header_offset)
        header = source.read(30)
        if len(header) != 30:
            raise ArchiveError(f'archive local header is truncated: {info.filename!r}')
        (
            signature,
            _version,
            flags,
            compression,
            _time,
            _date,
            crc32,
            compressed_size,
            file_size,
            name_length,
            extra_length,
        ) = struct.unpack('<IHHHHHIIIHH', header)
        if signature != 0x04034B50:
            raise ArchiveError(f'archive local header signature is invalid: {info.filename!r}')
        if extra_length > limits.max_extra_size:
            raise ArchiveError(f'archive local extra data exceeds the limit: {info.filename!r}')
        raw_name = source.read(name_length)
        if len(raw_name) != name_length:
            raise ArchiveError(f'archive local filename is truncated: {info.filename!r}')
        try:
            local_name = raw_name.decode('utf-8' if flags & 0x800 else 'cp437')
        except UnicodeDecodeError as error:
            raise ArchiveError(f'archive local filename is invalid: {info.filename!r}') from error
        _validate_name(local_name)
        if local_name != info.orig_filename:
            raise ArchiveError(f'archive local and central names differ: {info.filename!r}')
        if flags != info.flag_bits or compression != info.compress_type:
            raise ArchiveError(f'archive local and central metadata differ: {info.filename!r}')

        uses_descriptor = bool(flags & 0x08)
        if uses_descriptor:
            local_values = (crc32, compressed_size, file_size)
            central_values = (info.CRC, info.compress_size, info.file_size)
            if any(local not in (0, central) for local, central in zip(local_values, central_values)):
                raise ArchiveError(
                    f'archive local and central sizes differ: {info.filename!r}'
                )
        elif (
            crc32 != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
        ):
            raise ArchiveError(f'archive local and central sizes differ: {info.filename!r}')

        data_start = info.header_offset + 30 + name_length + extra_length
        data_end = data_start + info.compress_size
        boundary = (
            ordered[index + 1].header_offset
            if index + 1 < len(ordered)
            else central_directory_offset
        )
        if data_end > boundary or data_end > central_directory_offset:
            raise ArchiveError(f'archive member data exceeds its physical bounds: {info.filename!r}')
        if uses_descriptor:
            if max(info.compress_size, info.file_size) > 0xffffffff:
                raise ArchiveError(f'archive ZIP64 descriptor is unsupported: {info.filename!r}')
            descriptor = struct.pack('<III', info.CRC, info.compress_size, info.file_size)
            source.seek(data_end)
            available = source.read(min(16, boundary - data_end))
            signed_descriptor = b'PK\x07\x08' + descriptor
            if available.startswith(signed_descriptor):
                descriptor_end = data_end + len(signed_descriptor)
            elif available.startswith(descriptor):
                descriptor_end = data_end + len(descriptor)
            else:
                raise ArchiveError(f'archive data descriptor differs from central metadata: {info.filename!r}')
            if descriptor_end > boundary:
                raise ArchiveError(f'archive data descriptor exceeds its physical bounds: {info.filename!r}')
            data_end = descriptor_end
        ranges.append((info.header_offset, data_end, info.filename))

    previous_end = 0
    for start, end, name in sorted(ranges):
        if start < previous_end:
            raise ArchiveError(f'archive member data overlaps another member: {name!r}')
        previous_end = end


def _stream_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    limits: ArchiveLimits,
    already_streamed: int,
    collect: bool,
) -> tuple[int, bytes | None, str]:
    streamed = 0
    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if collect else None
    try:
        with archive.open(info, 'r') as source:
            while True:
                chunk = source.read(limits.chunk_size)
                if not chunk:
                    break
                streamed += len(chunk)
                digest.update(chunk)
                if streamed > info.file_size:
                    raise ArchiveError(f'archive member exceeded its declared size: {info.filename!r}')
                if already_streamed + streamed > limits.max_streamed_bytes:
                    raise ArchiveError('archive exceeds the streamed byte limit')
                if chunks is not None:
                    chunks.append(chunk)
    except (EOFError, RuntimeError, zipfile.BadZipFile, OSError, zlib.error) as error:
        raise ArchiveError(f'archive member failed CRC or is truncated: {info.filename!r}') from error
    if streamed != info.file_size:
        raise ArchiveError(f'archive member is truncated: {info.filename!r}')
    return streamed, b''.join(chunks) if chunks is not None else None, digest.hexdigest()


def _validated_allowlist(allowlisted_members: Iterable[str]) -> frozenset[str]:
    values = tuple(allowlisted_members)
    if len(values) != len(set(values)):
        raise ArchiveError('allowlisted member names must be unique')
    allowlist = frozenset(values)
    for name in allowlist:
        if _validate_name(name) != name:
            raise ArchiveError(f'allowlisted member is not NFC-normalized: {name!r}')
    return allowlist


def _inspect_open_archive(
    archive: zipfile.ZipFile,
    *,
    allowlist: frozenset[str],
    limits: ArchiveLimits,
    collect_members: frozenset[str] = frozenset(),
) -> tuple[InspectionResult, dict[str, bytes]]:
    infos = archive.infolist()
    _validate_infos(infos, allowlist, limits)
    if len(archive.comment) > limits.max_comment_size:
        raise ArchiveError('archive comment exceeds the size limit')
    if archive.fp is None:
        raise ArchiveError('archive was closed during inspection')
    _validate_physical_layout(archive.fp, infos, archive.start_dir, limits)
    streamed = 0
    members: list[InspectedMember] = []
    collected: dict[str, bytes] = {}
    for info in infos:
        member_digest = None
        count, data, digest = _stream_member(
            archive,
            info,
            limits=limits,
            already_streamed=streamed,
            collect=not info.is_dir() and info.filename in collect_members,
        )
        streamed += count
        if not info.is_dir():
            member_digest = digest
        if data is not None:
            collected[info.filename] = data
        members.append(InspectedMember(
            name=info.filename,
            size=info.file_size,
            compressed_size=info.compress_size,
            crc32=f'{info.CRC:08x}',
            sha256=member_digest,
        ))
    return InspectionResult(tuple(members), streamed), collected


def inspect_zip(
    path: Path,
    *,
    allowlisted_members: Iterable[str] = (),
    limits: ArchiveLimits = ArchiveLimits(),
) -> InspectionResult:
    """Validate all ZIP members and stream each file to force CRC checks."""

    allowlist = _validated_allowlist(allowlisted_members)
    try:
        with zipfile.ZipFile(path, 'r') as archive:
            result, _ = _inspect_open_archive(
                archive,
                allowlist=allowlist,
                limits=limits,
            )
    except (zipfile.BadZipFile, EOFError, OSError) as error:
        raise ArchiveError(f'invalid or truncated ZIP archive: {path}') from error
    return result


def read_allowlisted_members(
    path: Path,
    members: Iterable[str],
    *,
    allowlisted_members: Iterable[str],
    limits: ArchiveLimits = ArchiveLimits(),
) -> dict[str, bytes]:
    """Read allowlisted regular files after one complete archive inspection."""

    allowlist = _validated_allowlist(allowlisted_members)
    requested = _validated_allowlist(members)
    unallowlisted = requested - allowlist
    if unallowlisted:
        raise ArchiveError(
            f'member is not allowlisted: {sorted(unallowlisted)[0]!r}'
        )
    try:
        with zipfile.ZipFile(path, 'r') as archive:
            _, data = _inspect_open_archive(
                archive,
                allowlist=allowlist,
                limits=limits,
                collect_members=requested,
            )
    except (zipfile.BadZipFile, EOFError, OSError) as error:
        raise ArchiveError(f'invalid or truncated ZIP archive: {path}') from error
    missing = requested - set(data)
    if missing:
        raise ArchiveError(
            f'allowlisted member is not a regular file: {sorted(missing)[0]!r}'
        )
    return data


def read_allowlisted_member(
    path: Path,
    member: str,
    *,
    allowlisted_members: Iterable[str],
    limits: ArchiveLimits = ArchiveLimits(),
) -> bytes:
    """Read one exact member after validating and CRC-streaming the whole archive."""

    return read_allowlisted_members(
        path,
        (member,),
        allowlisted_members=allowlisted_members,
        limits=limits,
    )[member]
