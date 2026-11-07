# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Independent, test-only care-map oracle. Never imported by production code.

The source witness is a byte-exact reconstruction; synthetic sparse chunks
reproduce observed ranges but are NOT signed image bytes or their chunk map.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SOURCE_PROTO = FIXTURES / "pdx235_20261009.care_map.pb"
SOURCE_WITNESS = FIXTURES / "pdx235_20261009.json"
_NAME = re.compile(r"[a-z0-9_]{1,64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
MAX_EXTENT = 1 << 63
BLOCK_SIZE = 4096


def witness() -> dict:
    return json.loads(SOURCE_WITNESS.read_text(encoding="utf-8"))


def source_bytes() -> bytes:
    data = SOURCE_PROTO.read_bytes()
    f = witness()
    if len(data) != f["care_map_size_bytes"]:
        raise ValueError("authenticated care-map size witness mismatch")
    if hashlib.sha256(data).hexdigest() != f["care_map_sha256"]:
        raise ValueError("authenticated care-map digest witness mismatch")
    return data


def _varint(n: int) -> bytes:
    if not isinstance(n, int) or n < 0 or n >= 1 << 64:
        raise ValueError("invalid protobuf varint")
    parts = []
    while n >= 128:
        parts.append((n & 127) | 128)
        n >>= 7
    return bytes(parts + [n])


def _field(number: int, value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def encode_map(records: list[dict]) -> bytes:
    return b"".join(_field(1, b"".join(
        _field(i, item[key]) for i, key in enumerate(
            ("name", "ranges", "id", "fingerprint"), 1
        )
    )) for item in records)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError("protobuf varint overflow")
        value |= (byte & 127) << (7 * index)
        if not byte & 128:
            if _varint(value) != data[offset - index - 1:offset]:
                raise ValueError("noncanonical protobuf varint")
            return value, offset
    raise ValueError("oversized protobuf varint")


def _fields(data: bytes):
    offset = 0
    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        if tag >> 3 == 0 or tag & 7 != 2:
            raise ValueError("unexpected protobuf field/wire type")
        length, offset = _read_varint(data, offset)
        if length > len(data) - offset:
            raise ValueError("truncated protobuf field")
        yield tag >> 3, data[offset:offset + length]
        offset += length


def parse_ranges(raw: str, *, extent_blocks: int | None = None):
    """Parse canonical half-open raw RangeSet ranges (strict, no implicit merge)."""
    tokens = raw.split(",")
    if not tokens or any(not _DECIMAL.fullmatch(token) for token in tokens):
        raise ValueError("invalid decimal range encoding")
    numbers = [int(token) for token in tokens]
    if numbers[0] < 2 or numbers[0] % 2 or numbers[0] != len(numbers) - 1:
        raise ValueError("invalid range pair count")
    if extent_blocks is not None and not 0 < extent_blocks <= MAX_EXTENT:
        raise ValueError("invalid filesystem extent bound")
    previous = 0
    pairs = []
    for start, end in zip(numbers[1::2], numbers[2::2]):
        if start < previous or end <= start or end > MAX_EXTENT:
            raise ValueError("out-of-order/overlapping/empty range")
        if extent_blocks is not None and end > extent_blocks:
            raise ValueError("range exceeds original filesystem extent")
        pairs.append((start, end))
        previous = end
    return tuple(pairs)


def parse_map(data: bytes, *, limits: dict[str, int] | None = None):
    if not 0 < len(data) <= 1024 * 1024:
        raise ValueError("care map must be nonempty and bounded")
    result = {}
    for field_num, chunk in _fields(data):
        if field_num != 1 or len(chunk) > 8192 or len(result) >= 64:
            raise ValueError("invalid care-map partition field or count")
        fields = {}
        for number, value in _fields(chunk):
            if number not in (1, 2, 3, 4) or number in fields:
                raise ValueError("unknown or duplicate partition protobuf field")
            try:
                fields[number] = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("invalid partition string") from exc
        if set(fields) != {1, 2, 3, 4}:
            raise ValueError("missing partition protobuf field")
        name = fields[1]
        if not _NAME.fullmatch(name) or name in result:
            raise ValueError("invalid or duplicate partition name")
        if fields[3] != f"ro.{name}.build.fingerprint":
            raise ValueError("incorrect runtime property ID")
        fp = fields[4]
        if not 1 <= len(fp) <= 512 or not all(33 <= ord(c) <= 126 for c in fp):
            raise ValueError("invalid fingerprint value")
        parse_ranges(fields[2], extent_blocks=(limits or {}).get(name))
        result[name] = {
            "name": name, "ranges": fields[2], "id": fields[3],
            "fingerprint": fp,
        }
    if not result:
        raise ValueError("missing partitions")
    return result


def normalize(extents: list[tuple[int, int]], *, bound: int):
    """Require non-overlap; sort unordered extents and merge adjacent ones."""
    if not isinstance(bound, int) or not 0 < bound <= MAX_EXTENT:
        raise ValueError("bad extent bound")
    out = []
    for start, end in sorted(extents):
        if not isinstance(start, int) or not isinstance(end, int):
            raise ValueError("noninteger extent")
        if start < 0 or end <= start or end > bound:
            raise ValueError("invalid extent bounds")
        if out and start < out[-1][1]:
            raise ValueError("overlapping extents")
        if out and start == out[-1][1]:
            out[-1] = (out[-1][0], end)
        else:
            out.append((start, end))
    if not out:
        raise ValueError("care map cannot select zero blocks")
    return tuple(out)


def raw_ranges(extents) -> str:
    points = [v for pair in extents for v in pair]
    if not points:
        raise ValueError("empty care-map range set")
    return ",".join(map(str, (len(points), *points)))


def sparse_ranges(chunks: list[dict], *, total_blocks: int, image_size: int,
                  block_size: int = BLOCK_SIZE) -> str:
    """AOSP releasetools: RAW and FILL are meaningful; DONT_CARE is skipped.

    image_size is the AVB footer's *original filesystem image size*, not
    payload partition size including appended hashtree/FEC/footer.
    """
    if block_size <= 0 or image_size <= 0 or image_size % block_size:
        raise ValueError("unaligned original filesystem size")
    if total_blocks <= 0 or image_size // block_size > total_blocks:
        raise ValueError("original image outside sparse image")
    current = 0
    meaningful = []
    for chunk in chunks:
        kind, start, end = chunk["type"], chunk["start"], chunk["end"]
        if kind not in ("raw", "fill", "dontcare"):
            raise ValueError("unsupported sparse chunk")
        if not isinstance(start, int) or not isinstance(end, int):
            raise ValueError("noninteger sparse chunk bounds")
        if start != current or end <= start or end > total_blocks:
            raise ValueError("unordered, overlapping or missing sparse chunk")
        if kind != "dontcare":
            low, high = start, min(end, image_size // block_size)
            if high > low:
                meaningful.append((low, high))
        current = end
    if current != total_blocks:
        raise ValueError("sparse chunks do not cover image")
    return raw_ranges(normalize(meaningful, bound=image_size // block_size))


def contiguous_ranges(*, original_image_size: int, block_size: int = BLOCK_SIZE):
    if original_image_size <= 0 or original_image_size % block_size:
        raise ValueError("unaligned original filesystem size")
    return f"2,0,{original_image_size // block_size}"


def synthetic_chunks(raw: str, *, total_blocks: int):
    """Synthetic *range-derived* chunks, NOT recovered source sparse headers."""
    pairs = parse_ranges(raw, extent_blocks=total_blocks)
    result = []
    offset = 0
    for start, end in pairs:
        if start > offset:
            result.append({"type": "dontcare", "start": offset, "end": start})
        result.append({"type": "raw", "start": start, "end": end})
        offset = end
    if offset < total_blocks:
        result.append({"type": "dontcare", "start": offset, "end": total_blocks})
    return result


def request_for_partition(f: dict, part: dict, *, sparse: bool = True):
    blocks = parse_ranges(part["avb_v3_34_1_ranges"])[0][1]
    return {
        "schema": "modos-care-map-conformance-v1",
        "name": part["name"],
        "block_size": f["block_size"],
        "original_image_size": blocks * f["block_size"],
        "sparse_total_blocks": blocks if sparse else None,
        "sparse_chunks": synthetic_chunks(part["source_ranges"], total_blocks=blocks)
                         if sparse else None,
        "filesystem_property_id": f"ro.{part['name']}.build.fingerprint",
        "filesystem_fingerprint": f["source_fingerprint"],
        "avb_fingerprint": f["avb_v3_34_1_fingerprint"],
    }


def expected_output(req: dict):
    if req["schema"] != "modos-care-map-conformance-v1":
        raise ValueError("unexpected candidate schema")
    name, prop_id = req["name"], req["filesystem_property_id"]
    if not _NAME.fullmatch(name) or prop_id != f"ro.{name}.build.fingerprint":
        raise ValueError("invalid runtime property ID")
    fp = req["filesystem_fingerprint"]
    if not isinstance(fp, str) or not fp:
        raise ValueError("missing filesystem fingerprint")
    chunks = req["sparse_chunks"]
    if chunks is None:
        ranges = contiguous_ranges(original_image_size=req["original_image_size"],
                                   block_size=req["block_size"])
    else:
        ranges = sparse_ranges(
            chunks, total_blocks=req["sparse_total_blocks"],
            image_size=req["original_image_size"], block_size=req["block_size"]
        )
    return {"name": name, "ranges": ranges, "id": prop_id, "fingerprint": fp}


def runtime_selected(records: dict, properties: dict[str, str]) -> set[str]:
    """Model the exact property equality filter, not boot/device attestation."""
    return {
        name for name, part in records.items()
        if properties.get(part["id"], "") == part["fingerprint"]
    }
