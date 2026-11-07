# SPDX-FileCopyrightText: 2026 PixeneOS contributors
# SPDX-License-Identifier: GPL-3.0-only

"""Fail-closed runtime fingerprint identity guard for exceptional source OTAs.

This is a necessary *pre-publication* consistency check, not a device boot
attestation. Android's update_verifier selects blocks only when the care-map
fingerprint matches the runtime ro.<partition>.build.fingerprint property.
avbroot's default regeneration from AVB properties need not match that value.

The input source must have already passed the caller's authenticated source
verification. Never use this guard to waive avbroot signature, AVB, or image
verification, and never treat it as sufficient to authorize publication.
"""

from __future__ import annotations

from pathlib import Path
import re
import zipfile


_MAX_CARE_MAP_SIZE = 1024 * 1024
_MAX_PARTITIONS = 64
_MAX_PARTITION_BYTES = 8192
_NAME_PATTERN = re.compile(r'[a-z0-9_]{1,64}\Z')
_RANGE_PATTERN = re.compile(r'[0-9]+(?:,[0-9]+)*\Z')


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError('truncated protobuf varint')
        octet = data[offset]
        offset += 1
        if index == 9 and octet > 1:
            raise ValueError('protobuf varint overflow')
        value |= (octet & 0x7f) << (7 * index)
        if not octet & 0x80:
            return value, offset
    raise ValueError('protobuf varint too long')


def _length_fields(data: bytes):
    """Strictly decode the length-delimited-only care_map.proto schema."""
    offset = 0
    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number == 0 or wire != 2:
            raise ValueError('unexpected care_map protobuf field')
        size, offset = _read_varint(data, offset)
        if size > len(data) - offset:
            raise ValueError('care_map protobuf field outside data')
        yield number, data[offset:offset + size]
        offset += size


def _validate_ranges(value: str) -> None:
    if not _RANGE_PATTERN.fullmatch(value):
        raise ValueError('invalid care_map block-range encoding')
    values = list(map(int, value.split(',')))
    count = values[0]
    if count < 2 or count % 2 or count != len(values) - 1:
        raise ValueError('invalid care_map block-range count')
    previous_end = 0
    for index in range(1, len(values), 2):
        start, end = values[index], values[index + 1]
        if start < previous_end or end <= start or end > (1 << 63):
            raise ValueError('invalid care_map block-range extent')
        previous_end = end


def parse_care_map(data: bytes) -> dict[str, dict[str, str]]:
    partitions: dict[str, dict[str, str]] = {}
    for number, raw in _length_fields(data):
        if number != 1:
            raise ValueError('unexpected top-level care_map field')
        if len(raw) > _MAX_PARTITION_BYTES:
            raise ValueError('care_map partition record too large')
        fields: dict[int, str] = {}
        for number, encoded in _length_fields(raw):
            if number not in (1, 2, 3, 4) or number in fields:
                raise ValueError('unknown or duplicate care_map partition field')
            fields[number] = encoded.decode('utf-8')
        if set(fields) != {1, 2, 3, 4}:
            raise ValueError('incomplete care_map partition')
        name, ranges, property_id, fingerprint = (
            fields[1], fields[2], fields[3], fields[4]
        )
        if not _NAME_PATTERN.fullmatch(name) or name in partitions:
            raise ValueError('invalid or duplicate care_map partition name')
        if property_id != f'ro.{name}.build.fingerprint':
            raise ValueError(f'unexpected care_map fingerprint property ID: {name}')
        if not 1 <= len(fingerprint) <= 512 or any(
            ord(character) < 33 or ord(character) > 126
            for character in fingerprint
        ):
            raise ValueError(f'invalid care_map fingerprint value: {name}')
        _validate_ranges(ranges)
        partitions[name] = dict(name=name, ranges=ranges, id=property_id, fingerprint=fingerprint)
        if len(partitions) > _MAX_PARTITIONS:
            raise ValueError('too many care_map partitions')
    if not partitions:
        raise ValueError('empty care_map partition set')
    return partitions


def read_care_map(ota: Path) -> dict[str, dict[str, str]]:
    """Read the *unique* nonempty map, without extracting or modifying images."""
    with zipfile.ZipFile(ota, 'r') as archive:
        matches = [i for i in archive.infolist() if i.filename == 'care_map.pb']
        if (
            len(matches) != 1
            or matches[0].is_dir()
            or not 0 < matches[0].file_size <= _MAX_CARE_MAP_SIZE
        ):
            raise ValueError('OTA must contain exactly one bounded, nonempty care_map.pb')
        data = archive.read(matches[0])
    return parse_care_map(data)


def read_fingerprint_identities(ota: Path) -> dict[str, tuple[str, str]]:
    return {name: (entry['id'], entry['fingerprint'])
            for name, entry in read_care_map(ota).items()}


def verify_fingerprint_identity_preserved(
    source_ota: Path,
    regenerated_ota: Path,
) -> None:
    """Refuse an output whose care map changes authenticated source identities.

    Range regeneration can be legitimate and is intentionally compared by
    avbroot's *separate strict output verifier*, not by this function.
    This guard is deliberately conservative: if a patch intentionally changes
    a runtime fingerprint, it needs independent device-specific review rather
    than silently relaxing first-boot verification.
    """
    try:
        original = read_fingerprint_identities(source_ota)
        regenerated = read_fingerprint_identities(regenerated_ota)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f'cannot establish care_map.pb runtime identities: {exc}') from exc

    if original != regenerated:
        names = sorted(original.keys() | regenerated.keys())
        changed = [
            name for name in names
            if original.get(name) != regenerated.get(name)
        ]
        raise RuntimeError(
            'regenerated care_map.pb changes runtime fingerprint identity '
            f'for: {", ".join(changed)}. Android update_verifier can skip '
            'partition verification when a map fingerprint does not match '
            'ro.<partition>.build.fingerprint. Refusing output.'
        )
