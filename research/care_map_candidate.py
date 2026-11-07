#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Offline Worklane 1 candidate adapter for Worklane 3's independent tests.

Accepts the two *synthetic test* protocols:
  modos-care-map-conformance-v1 (AOSP sparse chunk semantics)
  modos-care-map-provenance-v1 (D subset signed-source sparse ranges)

CRITICAL: The JSON manifest digests and filesystem properties are UNTRUSTED
CALLER INPUT. This adapter neither validates signatures nor reads the actual
filesystem build.prop, and MUST NOT be wired to production/publishing paths.
It exercises care_map_prototype.py and does not import the independent oracle.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

from care_map_prototype import (
    BLOCK_SIZE, CareMapUnsafe, ImageEvidence, parse_map, parse_ranges,
    verify_output_map,
)

_MAX_REQUEST = 12 * 1024 * 1024
_MAX_IMAGE = 2 * 1024 * 1024  # This adapter is for tiny synthetic fixtures only.
_NAME = re.compile(r'[a-z0-9_]{1,64}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')


def _error(message: str) -> None:
    raise CareMapUnsafe(message)


def _obj(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            _error(f'duplicate JSON object key: {key}')
        result[key] = value
    return result


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        _error(f'{name}: expected string')
    return value


def _positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        _error(f'{name}: expected positive integer')
    return value


def _name(value: Any) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        _error('invalid partition name')
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        _error(f'{name}: missing or invalid expected SHA-256')
    return value


def _fp(value: Any, name: str) -> str:
    value = _text(value, name)
    if not value or len(value) > 512 or value == 'unknown' or not all(
        33 <= ord(ch) <= 126 for ch in value
    ):
        _error(f'{name}: invalid filesystem fingerprint')
    return value


def _b64(value: Any, name: str, *, max_bytes: int) -> bytes:
    s = _text(value, name)
    if len(s) > ((max_bytes + 2) // 3) * 4 or not s:
        _error(f'{name}: empty or oversized base64 field')
    try:
        result = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CareMapUnsafe(f'{name}: malformed base64') from exc
    if not 0 < len(result) <= max_bytes:
        _error(f'{name}: decoded field empty or oversized')
    return result


def _names(value: Any, label: str) -> set[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        _error(f'{label}: absent or excessive manifest partition list')
    parsed = [_name(name) for name in value]
    if len(set(parsed)) != len(parsed):
        _error(f'{label}: duplicate partition names')
    return set(parsed)


def _conformance(req: dict) -> dict:
    name = _name(req.get('name'))
    block_size = _positive_int(req.get('block_size'), 'block_size')
    if block_size != BLOCK_SIZE:
        _error('update_verifier uses 4096-byte blocks')
    size = _positive_int(req.get('original_image_size'), 'original_image_size')
    if size % BLOCK_SIZE:
        _error('unaligned original filesystem image size')
    count = size // BLOCK_SIZE
    prop_id = f'ro.{name}.build.fingerprint'
    if req.get('filesystem_property_id') != prop_id:
        _error('invalid filesystem property ID')
    fingerprint = _fp(req.get('filesystem_fingerprint'), 'filesystem_fingerprint')
    # Deliberately do not derive identities from the AVB field; only validate type.
    _text(req.get('avb_fingerprint'), 'avb_fingerprint')
    sparse_chunks = req.get('sparse_chunks')
    sparse_total = req.get('sparse_total_blocks')
    if sparse_chunks is None:
        if sparse_total is not None:
            _error('sparse_total_blocks without sparse_chunks')
        ranges = f'2,0,{count}'
    else:
        total = _positive_int(sparse_total, 'sparse_total_blocks')
        if not isinstance(sparse_chunks, list) or not sparse_chunks or total < count:
            _error('missing sparse chunks or insufficient partition blocks')
        if len(sparse_chunks) > 65536:
            _error('too many sparse chunks')
        previous = 0
        meaningful: list[tuple[int, int]] = []
        for chunk in sparse_chunks:
            if not isinstance(chunk, dict):
                _error('malformed sparse chunk')
            kind = chunk.get('type')
            start = chunk.get('start')
            end = chunk.get('end')
            if kind not in ('raw', 'fill', 'dontcare') or type(start) is not int or type(end) is not int:
                _error('invalid sparse chunk type or endpoints')
            if start != previous or end <= start or end > total:
                _error('sparse chunks must cover sequential nonoverlapping blocks')
            if kind != 'dontcare' and start < count:
                lo, hi = start, min(end, count)
                if meaningful and meaningful[-1][1] == lo:
                    meaningful[-1] = meaningful[-1][0], hi
                else:
                    meaningful.append((lo, hi))
            previous = end
        if previous != total or not meaningful:
            _error('sparse chunks do not fully cover or select any protected data')
        bounds = [v for s, e in meaningful for v in (s, e)]
        ranges = ','.join(map(str, (len(bounds), *bounds)))
    parse_ranges(ranges, count)
    return {'name': name, 'ranges': ranges, 'id': prop_id, 'fingerprint': fingerprint}


def _provenance(req: dict) -> dict:
    if _positive_int(req.get('block_size'), 'block_size') != BLOCK_SIZE:
        _error('unsupported block size')
    source_map = _b64(req.get('source_care_map_b64'), 'source_care_map_b64', max_bytes=1024 * 1024)
    candidate_map = _b64(req.get('candidate_output_care_map_b64'),
                         'candidate_output_care_map_b64', max_bytes=1024 * 1024)
    source_map_sha = _sha(req.get('source_care_map_sha256'), 'source_care_map_sha256')
    if hashlib.sha256(source_map).hexdigest() != source_map_sha:
        _error('source care map SHA-256 disagrees with expected source member')
    source_names = _names(req.get('source_manifest_dynamic_partitions'), 'source')
    output_names = _names(req.get('output_manifest_dynamic_partitions'), 'output')
    raw_partitions = req.get('partitions')
    if not isinstance(raw_partitions, list) or len(raw_partitions) != len(source_names):
        _error('invalid partition evidence list')
    inputs: dict[str, ImageEvidence] = {}
    outputs: dict[str, ImageEvidence] = {}
    synthetic_fingerprints: dict[Path, str] = {}
    report_data = {}
    with tempfile.TemporaryDirectory(prefix='modos-care-map-candidate-') as root:
        for index, record in enumerate(raw_partitions):
            if not isinstance(record, dict):
                _error('invalid partition evidence record')
            name = _name(record.get('name'))
            if name in inputs:
                _error(f'{name}: duplicate image evidence')
            prop_id = f'ro.{name}.build.fingerprint'
            if (record.get('source_property_id') != prop_id
                    or record.get('output_property_id') != prop_id):
                _error(f'{name}: property ID does not match runtime identity')
            if (record.get('source_filesystem_type') != 'ext4'
                    or record.get('output_filesystem_type') != 'ext4'):
                _error(f'{name}: unsupported filesystem')
            source_fp = _fp(record.get('source_filesystem_fingerprint'), f'{name} source property')
            output_fp = _fp(record.get('output_filesystem_fingerprint'), f'{name} output property')
            # pdx235 compat policy: unchanged runtime identities, unlike generic
            # prototype's capability for separately reviewed real property edits.
            if source_fp != output_fp:
                _error(f'{name}: output runtime fingerprint drift')
            a = _b64(record.get('source_image_b64'), f'{name} source image', max_bytes=_MAX_IMAGE)
            b = _b64(record.get('output_image_b64'), f'{name} output image', max_bytes=_MAX_IMAGE)
            if len(a) != len(b):
                _error(f'{name}: changed partition image size')
            source_path = Path(root) / f'{index}-source.img'
            output_path = Path(root) / f'{index}-output.img'
            source_path.write_bytes(a)
            output_path.write_bytes(b)
            inputs[name] = ImageEvidence(
                source_path,
                _sha(record.get('source_manifest_sha256'), f'{name} source manifest SHA-256'),
                _positive_int(record.get('source_hashtree_image_size'), f'{name} source hashtree extent'),
                '/build.prop',
                _positive_int(record.get('source_footer_original_size'), f'{name} source footer extent'),
                _positive_int(record.get('source_manifest_size'), f'{name} source manifest size'),
            )
            outputs[name] = ImageEvidence(
                output_path,
                _sha(record.get('output_manifest_sha256'), f'{name} output manifest SHA-256'),
                _positive_int(record.get('output_hashtree_image_size'), f'{name} output hashtree extent'),
                '/build.prop',
                _positive_int(record.get('output_footer_original_size'), f'{name} output footer extent'),
                _positive_int(record.get('output_manifest_size'), f'{name} output manifest size'),
            )
            synthetic_fingerprints[source_path] = source_fp
            synthetic_fingerprints[output_path] = output_fp
            report_data[name] = (source_fp, output_fp)

        if source_names != output_names or source_names != set(inputs):
            _error('source/output manifest partitions disagree with evidence')
        source_entries = parse_map(source_map)
        if set(source_entries) != source_names:
            _error('source map partition names disagree with authenticated source manifest')
        # This is a synthetic adapter. The property-reader injection is explicitly
        # NOT an authenticated filesystem property extraction. Never ship this.
        def synthetic_reader(image: ImageEvidence, name: str) -> str:
            return synthetic_fingerprints[image.image]

        changed = verify_output_map(
            source_map, candidate_map, inputs, outputs, source_names,
            property_reader=synthetic_reader,
        )
        # Require unchanged identities for the currently scoped pdx235 source;
        # any generic changed-property allowance needs a separate policy review.
        if parse_map(candidate_map) != source_entries:
            _error('candidate care map identities/ranges changed')
        partitions = []
        for name in sorted(source_names):
            a, b = inputs[name], outputs[name]
            source_fp, output_fp = report_data[name]
            partitions.append({
                'name': name,
                'source_image_sha256': a.manifest_sha256,
                'output_image_sha256': b.manifest_sha256,
                'source_image_size': a.manifest_image_bytes,
                'output_image_size': b.manifest_image_bytes,
                'hashtree_image_size': a.verity_data_bytes,
                'footer_original_image_size': a.footer_original_bytes,
                'property_id': f'ro.{name}.build.fingerprint',
                'source_fingerprint': source_fp,
                'output_fingerprint': output_fp,
                'ranges': source_entries[name].ranges,
                'changed_protected_blocks': changed[name],
            })
        return {
            'schema': 'modos-care-map-preservation-proof-v1',
            'source_care_map_sha256': source_map_sha,
            'candidate_care_map_matches_source_semantics': True,
            'partitions': partitions,
            'note': 'SYNTHETIC only: neither signed-manifest provenance nor effective runtime properties are verified',
        }


def run(request: dict) -> dict:
    if not isinstance(request, dict):
        _error('top-level request must be JSON object')
    schema = request.get('schema')
    if schema == 'modos-care-map-conformance-v1':
        return _conformance(request)
    if schema == 'modos-care-map-provenance-v1':
        return _provenance(request)
    _error(f'unsupported schema: {schema!r}')


def main() -> int:
    if sys.argv[1:] not in ([], ['--json']):
        print('usage: care_map_candidate.py [--json]', file=sys.stderr)
        return 2
    try:
        raw = sys.stdin.buffer.read(_MAX_REQUEST + 1)
        if not raw or len(raw) > _MAX_REQUEST:
            _error('request absent or too large')
        req = json.loads(raw.decode('utf-8'), object_pairs_hook=_obj,
                         parse_constant=lambda _: _error('nonfinite JSON number'))
        result = run(req)
    except (ValueError, TypeError, KeyError, OSError, UnicodeError) as ex:
        print(f'care-map candidate rejected input: {ex}', file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(',', ':'), sort_keys=True, allow_nan=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())