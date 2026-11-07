# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Research-only fail-closed care-map provenance prototype.

NOT A DROP-IN REPLACEMENT FOR avbroot ota verify. Caller must first independently
validate the signed source OTA and both signed payload/AVB chains, and supply
manifest-verified image SHA-256 digests. This prototype proves a conservative
reuse of publisher-authenticated sparse ranges, then derives fingerprints
from the actual read-only filesystem build.prop in each final image.

Ext4 build.prop extraction uses debugfs. Other filesystems fail closed until
an audited reader is available. No source or output image is ever modified.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable, Mapping

BLOCK_SIZE = 4096  # Android update_verifier uses 4096 bytes, independent of payload settings.
_MAX_MAP = 1024 * 1024
_MAX_PARTITIONS = 64
_MAX_PARTITION_RECORD = 128 * 1024
_MAX_BUILD_PROP = 1024 * 1024
_VALID_NAME = re.compile(r"[a-z0-9_]{1,64}\Z")
_VALID_PROP_PATH = re.compile(r"/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+\Z")
_VALID_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_VALID_RANGES = re.compile(r"(?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*))*\Z")


class CareMapUnsafe(ValueError):
    """Metadata or image evidence does not satisfy the conservative proof."""


@dataclass(frozen=True)
class PartitionEntry:
    name: str
    ranges: str
    id: str
    fingerprint: str


@dataclass(frozen=True)
class ImageEvidence:
    image: Path
    manifest_sha256: str  # Expected image digest from externally verified signed payload.
    verity_data_bytes: int  # Independently verified AVB hashtree image_size.
    build_prop_path: str  # Explicit canonical path inside the ext4 image.
    footer_original_bytes: int  # Independently parsed AVB footer original_image_size.
    manifest_image_bytes: int  # Independently verified signed manifest partition size.


def _valid_fingerprint(fingerprint: str) -> bool:
    return 0 < len(fingerprint) <= 512 and all(33 <= ord(c) <= 126 for c in fingerprint)


def _varint_decode(data: bytes, pos: int) -> tuple[int, int]:
    start = pos
    value = 0
    for i in range(10):
        if pos >= len(data):
            raise CareMapUnsafe("Truncated protobuf varint")
        b = data[pos]
        pos += 1
        if i == 9 and b > 1:
            raise CareMapUnsafe("Protobuf varint overflow")
        value |= (b & 127) << (7 * i)
        if not (b & 128):
            # Reject duplicate encodings. Canonical serialization is required.
            if data[start:pos] != _varint_encode(value):
                raise CareMapUnsafe("Noncanonical protobuf varint")
            return value, pos
    raise CareMapUnsafe("Protobuf varint too long")


def _varint_encode(value: int) -> bytes:
    if value < 0:
        raise CareMapUnsafe("Negative varint")
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def _fields(data: bytes):
    pos = 0
    while pos < len(data):
        tag, pos = _varint_decode(data, pos)
        number, wire_type = tag >> 3, tag & 7
        if number == 0 or wire_type != 2:
            raise CareMapUnsafe("Unknown protobuf field or wire type")
        length, pos = _varint_decode(data, pos)
        if length > len(data) - pos:
            raise CareMapUnsafe("Truncated protobuf string")
        yield number, data[pos:pos + length]
        pos += length


def _wire_field(number: int, payload: bytes) -> bytes:
    return _varint_encode((number << 3) | 2) + _varint_encode(len(payload)) + payload


def parse_ranges(value: str, image_blocks: int) -> tuple[tuple[int, int], ...]:
    """AOSP raw RangeSet: count,start,end,...; ends are exclusive."""
    if not _VALID_RANGES.fullmatch(value):
        raise CareMapUnsafe("Malformed care-map range syntax")
    if len(value) > _MAX_PARTITION_RECORD:
        raise CareMapUnsafe("Oversized care-map ranges")
    values = tuple(int(x) for x in value.split(","))
    if values[0] < 2 or values[0] % 2 or values[0] != len(values) - 1:
        raise CareMapUnsafe("Incorrect care-map range count")
    previous_end = 0
    parsed = []
    for i in range(1, len(values), 2):
        start, end = values[i:i + 2]
        if start < previous_end or end <= start or end > image_blocks:
            raise CareMapUnsafe("Invalid, overlapping, or out-of-bounds care range")
        parsed.append((start, end))
        previous_end = end
    return tuple(parsed)


def parse_map(data: bytes) -> dict[str, PartitionEntry]:
    if not 0 < len(data) <= _MAX_MAP:
        raise CareMapUnsafe("Care map must be nonempty and bounded")
    result: dict[str, PartitionEntry] = {}
    for number, data_partition in _fields(data):
        if number != 1 or len(data_partition) > _MAX_PARTITION_RECORD:
            raise CareMapUnsafe("Unexpected care-map partition field/size")
        f: dict[int, str] = {}
        for field, val in _fields(data_partition):
            if field not in (1, 2, 3, 4) or field in f:
                raise CareMapUnsafe("Unknown or duplicate partition field")
            try:
                f[field] = val.decode("utf-8", errors="strict")
            except UnicodeError as ex:
                raise CareMapUnsafe("Invalid UTF-8 in care map") from ex
        if set(f) != {1, 2, 3, 4}:
            raise CareMapUnsafe("Incomplete care-map partition")
        entry = PartitionEntry(f[1], f[2], f[3], f[4])
        if not _VALID_NAME.fullmatch(entry.name) or entry.name in result:
            raise CareMapUnsafe("Invalid/duplicate care-map partition name")
        if entry.id != f"ro.{entry.name}.build.fingerprint":
            raise CareMapUnsafe("Missing or wrong runtime property ID")
        if not _valid_fingerprint(entry.fingerprint) or entry.fingerprint == "unknown":
            raise CareMapUnsafe("Unsafe or absent runtime fingerprint")
        # Structural syntax here; image-specific bounds are checked later.
        parse_ranges(entry.ranges, (1 << 63) - 1)
        if len(entry.ranges) > _MAX_PARTITION_RECORD:
            raise CareMapUnsafe("Oversized care-map ranges")
        result[entry.name] = entry
        if len(result) > _MAX_PARTITIONS:
            raise CareMapUnsafe("Too many care-map partitions")
    if not result:
        raise CareMapUnsafe("Empty care-map partition list")
    return result


def serialize_map(entries: Mapping[str, PartitionEntry]) -> bytes:
    data = bytearray()
    for name, p in sorted(entries.items()):
        if name != p.name:
            raise CareMapUnsafe("Partition map key/name disagree")
        part = b"".join(_wire_field(i, v.encode("utf-8")) for i, v in (
            (1, p.name), (2, p.ranges), (3, p.id), (4, p.fingerprint)
        ))
        data.extend(_wire_field(1, part))
    encoded = bytes(data)
    # A strict decode protects against accidental serialization omissions.
    if parse_map(encoded) != dict(entries):
        raise CareMapUnsafe("Care-map protobuf serialization error")
    return encoded


def _ensure_image(evidence: ImageEvidence) -> int:
    image = evidence.image
    try:
        st = image.lstat()
    except OSError as ex:
        raise CareMapUnsafe(f"Image inaccessible: {image}") from ex
    if not stat.S_ISREG(st.st_mode) or image.is_symlink():
        raise CareMapUnsafe(f"Image must be a regular non-symlink file: {image}")
    if not _VALID_DIGEST.fullmatch(evidence.manifest_sha256):
        raise CareMapUnsafe("Invalid signed payload image SHA-256")
    if (evidence.verity_data_bytes <= 0
            or evidence.verity_data_bytes % BLOCK_SIZE
            or evidence.verity_data_bytes > st.st_size
            or evidence.footer_original_bytes != evidence.verity_data_bytes
            or evidence.manifest_image_bytes != st.st_size):
        raise CareMapUnsafe("Inconsistent signed manifest size or AVB hashtree/footer data extents")
    if not _VALID_PROP_PATH.fullmatch(evidence.build_prop_path):
        raise CareMapUnsafe("Unsafe build.prop path")
    h = hashlib.sha256()
    with image.open("rb") as stream:
        # Input to this prototype must be raw, not Android sparse.
        if stream.read(4) == b"\x3a\xff\x26\xed":
            raise CareMapUnsafe("Android sparse image provided; raw extraction required")
        stream.seek(0)
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != evidence.manifest_sha256:
        raise CareMapUnsafe(f"Image digest differs from signed payload manifest: {image}")
    if image.stat().st_size != st.st_size:
        raise CareMapUnsafe("Image changed during verification")
    return st.st_size


def debugfs_build_fingerprint(evidence: ImageEvidence, name: str) -> str:
    """Read the partition runtime property from its verified raw ext4 image.

    debugfs is a read-only tool here: no `-w` and no shell invocation.
    No automatic filesystem or AVB-property fallback is allowed.
    """
    # _ensure_image() and the caller's SHA-256 checks must precede this call.
    try:
        p = subprocess.run(
            ["debugfs", "-R", f"cat {evidence.build_prop_path}", str(evidence.image)],
            capture_output=True, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise CareMapUnsafe("Cannot read ext4 build.prop via debugfs") from ex
    if p.returncode or len(p.stdout) > _MAX_BUILD_PROP or not p.stdout:
        raise CareMapUnsafe("Failed to read a bounded filesystem build.prop")
    # debugfs can return exit code 0 for a missing path; reject reported errors.
    err = p.stderr.lower()
    if any(s in err for s in (b"file not found", b"not found by ext2_lookup", b"bad magic",
                                  b"invalid inode", b"filesystem not open", b"command not found")):
        raise CareMapUnsafe("debugfs could not resolve the expected build.prop")
    if b"\x00" in p.stdout:
        raise CareMapUnsafe("NUL byte in filesystem build.prop")
    try:
        content = p.stdout.decode("utf-8")
    except UnicodeDecodeError as ex:
        raise CareMapUnsafe("build.prop is not UTF-8") from ex
    key = f"ro.{name}.build.fingerprint"
    found = []
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, val = line.split("=", 1)
        if k.strip() == key:
            found.append(val.strip())
    if len(found) != 1 or not _valid_fingerprint(found[0]) or found[0] == "unknown":
        raise CareMapUnsafe(f"Missing, invalid, or duplicate {key} in actual filesystem")
    return found[0]


def _assert_diff_within_cared_ranges(
    source: ImageEvidence,
    output: ImageEvidence,
    ranges: tuple[tuple[int, int], ...],
) -> int:
    """Check *every* protected data block against the authenticated source.

    An image can change only in blocks already meaningful in the source sparse
    image. AVB footer, hash-tree, and FEC changes must be verified separately.
    """
    starts = [start for start, _ in ranges]
    changed = 0
    with source.image.open("rb") as a, output.image.open("rb") as b:
        for chunk_start in range(0, source.verity_data_bytes, 4 * 1024 * 1024):
            size = min(4 * 1024 * 1024, source.verity_data_bytes - chunk_start)
            a_chunk = a.read(size)
            b_chunk = b.read(size)
            if len(a_chunk) != size or len(b_chunk) != size:
                raise CareMapUnsafe("Truncated protected filesystem content")
            if a_chunk == b_chunk:
                continue
            for offset in range(0, size, BLOCK_SIZE):
                if a_chunk[offset:offset + BLOCK_SIZE] == b_chunk[offset:offset + BLOCK_SIZE]:
                    continue
                block = (chunk_start + offset) // BLOCK_SIZE
                index = bisect_right(starts, block) - 1
                if index < 0 or block >= ranges[index][1]:
                    raise CareMapUnsafe(
                        f"Changed block {block} lies outside authenticated sparse care ranges"
                    )
                changed += 1
    return changed


def regenerate_with_sparse_proof(
    source_care_map: bytes,
    source_images: Mapping[str, ImageEvidence],
    output_images: Mapping[str, ImageEvidence],
    signed_dynamic_partitions: set[str],
    property_reader: Callable[[ImageEvidence, str], str] = debugfs_build_fingerprint,
) -> tuple[bytes, dict[str, int]]:
    """Conservatively regenerate final care-map identities, preserve sparse ranges.

    signed_dynamic_partitions MUST come from the authenticated OTA manifest,
    never from care_map.pb itself. SHA-256 expectations MUST be bound to
    signature-verified payload manifests; accepting caller-provided hashes
    without verifying the manifest is not safe.
    """
    source_map = parse_map(source_care_map)
    expected = set(source_map)
    if (expected != signed_dynamic_partitions or set(source_images) != expected
            or set(output_images) != expected):
        raise CareMapUnsafe("Source map / signed dynamic partitions / extracted images differ")
    regenerated: dict[str, PartitionEntry] = {}
    changed_blocks: dict[str, int] = {}
    for name in sorted(expected):
        source = source_images[name]
        output = output_images[name]
        size_a = _ensure_image(source)
        size_b = _ensure_image(output)
        if size_a != size_b or source.verity_data_bytes != output.verity_data_bytes:
            raise CareMapUnsafe(f"Layout changed; sparse provenance cannot be reused: {name}")
        raw_ranges = source_map[name].ranges
        ranges = parse_ranges(raw_ranges, source.verity_data_bytes // BLOCK_SIZE)
        original_fp = property_reader(source, name)
        if original_fp != source_map[name].fingerprint:
            raise CareMapUnsafe(f"Original publisher care-map fingerprint disagrees with filesystem: {name}")
        final_fp = property_reader(output, name)
        if not _valid_fingerprint(final_fp) or final_fp == "unknown":
            raise CareMapUnsafe(f"Invalid final filesystem fingerprint: {name}")
        count = _assert_diff_within_cared_ranges(source, output, ranges)
        # Detect ordinary concurrent modifications while evidence is inspected.
        _ensure_image(source)
        _ensure_image(output)
        regenerated[name] = PartitionEntry(name, raw_ranges, f"ro.{name}.build.fingerprint", final_fp)
        changed_blocks[name] = count
    return serialize_map(regenerated), changed_blocks


def verify_output_map(
    source_care_map: bytes,
    output_care_map: bytes,
    source_images: Mapping[str, ImageEvidence],
    output_images: Mapping[str, ImageEvidence],
    signed_dynamic_partitions: set[str],
    property_reader: Callable[[ImageEvidence, str], str] = debugfs_build_fingerprint,
) -> dict[str, int]:
    expected_bytes, changed = regenerate_with_sparse_proof(
        source_care_map, source_images, output_images,
        signed_dynamic_partitions, property_reader,
    )
    if parse_map(output_care_map) != parse_map(expected_bytes):
        raise CareMapUnsafe("Output care-map fingerprint, ID, partition set, or ranges differ")
    return changed