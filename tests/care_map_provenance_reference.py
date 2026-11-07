# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Independent research oracle for the Worklane 1 D_p subset S_p rule.

TEST-ONLY. Inputs called "signed manifest" are *expected* digests/sizes
delivered by an external, independent signature verifier. This module cannot
authenticate a manifest, a publisher, an AVB chain, or an effective runtime
property. Neither this oracle nor passing synthetic tests authorize a build.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Mapping, Sequence

from tests import care_map_reference as legacy


@dataclass(frozen=True)
class ImageEvidence:
    """Bytes and metadata witnessed *after* the caller authenticates manifests.

    Real images must be streamed rather than materialized as bytes; this
    dataclass deliberately supports only small deterministic test images.
    """
    source: bytes
    output: bytes
    source_manifest_sha256: str
    output_manifest_sha256: str
    source_manifest_size: int
    output_manifest_size: int
    source_footer_original_size: int
    output_footer_original_size: int
    source_hashtree_image_size: int
    output_hashtree_image_size: int
    source_property_id: str | None
    output_property_id: str | None
    source_filesystem_fingerprint: str | None
    output_filesystem_fingerprint: str | None
    source_filesystem_type: str = "ext4"
    output_filesystem_type: str = "ext4"


def _check_sha256(data: bytes, expected_sha: str, label: str) -> str:
    if (
        not isinstance(expected_sha, str)
        or len(expected_sha) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha)
    ):
        raise ValueError(f"{label}: unsigned, missing or invalid manifest digest")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha:
        raise ValueError(f"{label}: image SHA-256 not bound to verified manifest")
    return actual


def _check_names(names: Sequence[str], label: str) -> set[str]:
    if not isinstance(names, (list, tuple)) or not names:
        raise ValueError(f"{label}: missing dynamic partition list")
    result = set(names)
    if len(result) != len(names) or not all(
        isinstance(n, str) and 1 <= len(n) <= 64 for n in names
    ):
        raise ValueError(f"{label}: duplicate/invalid dynamic partition names")
    return result


def _changed_blocks(source: bytes, output: bytes, bound: int,
                    care_ranges: tuple[tuple[int, int], ...], block_size: int):
    """Compare *every* protected block, including holes; fail at first gap."""
    count = 0
    cursor = 0
    for block in range(bound):
        while cursor < len(care_ranges) and block >= care_ranges[cursor][1]:
            cursor += 1
        a, b = block * block_size, (block + 1) * block_size
        if source[a:b] == output[a:b]:
            continue
        if cursor == len(care_ranges) or block < care_ranges[cursor][0]:
            raise ValueError(
                f"protected block {block} changed outside authenticated source ranges"
            )
        count += 1
    return count


def prove_preserved_ranges(
    *,
    source_care_map: bytes,
    candidate_output_care_map: bytes,
    source_care_map_sha256: str,
    source_manifest_partitions: Sequence[str],
    output_manifest_partitions: Sequence[str],
    partitions: Mapping[str, ImageEvidence],
    block_size: int = 4096,
) -> dict:
    """Demonstrate a conservative *conditional* preservation proof.

    A trusted external boundary must authenticate source publisher, source and
    output payload manifests, AVB signatures and the measured filesystem
    properties. Passing caller-provided hashes alone is NOT that verification.
    """
    if block_size != 4096:
        raise ValueError("unsupported/non-4096 care-map block size")
    if not 0 < len(source_care_map) <= 1024 * 1024:
        raise ValueError("missing/bounded source care map")
    _check_sha256(source_care_map, source_care_map_sha256, "source care-map")

    source_map = legacy.parse_map(source_care_map)
    final_map = legacy.parse_map(candidate_output_care_map)
    source_names = _check_names(source_manifest_partitions, "source manifest")
    output_names = _check_names(output_manifest_partitions, "output manifest")
    if (source_names != output_names
            or source_names != source_map.keys()
            or source_names != partitions.keys()):
        raise ValueError("missing/extra dynamic partition or manifest drift")
    if final_map != source_map:
        raise ValueError("candidate care-map partition/id/fingerprint/range drift")

    report = []
    for name in sorted(source_names):
        record = source_map[name]
        e = partitions[name]
        if not isinstance(e, ImageEvidence):
            raise ValueError(f"{name}: evidence missing or untyped")
        expected_id = f"ro.{name}.build.fingerprint"
        if (e.source_property_id != expected_id
                or e.output_property_id != expected_id):
            raise ValueError(f"{name}: incorrect/missing filesystem property ID")
        if (e.source_filesystem_fingerprint != record["fingerprint"]
                or e.output_filesystem_fingerprint != record["fingerprint"]):
            raise ValueError(f"{name}: actual filesystem fingerprint drift")
        if (e.source_filesystem_type != "ext4"
                or e.output_filesystem_type != "ext4"):
            raise ValueError(f"{name}: unsupported filesystem")
        sizes = (
            e.source_footer_original_size,
            e.output_footer_original_size,
            e.source_hashtree_image_size,
            e.output_hashtree_image_size,
        )
        if any(type(s) is not int or s <= 0 or s % block_size for s in sizes):
            raise ValueError(f"{name}: missing/unaligned AVB data extent")
        if len(set(sizes)) != 1:
            raise ValueError(f"{name}: protected extents or AVB footer drift")
        if (len(e.source) != e.source_manifest_size
                or len(e.output) != e.output_manifest_size
                or e.source_manifest_size != e.output_manifest_size
                or e.source_manifest_size < sizes[0]):
            raise ValueError(f"{name}: source/final whole-image layout or size drift")

        source_hash = _check_sha256(e.source, e.source_manifest_sha256,
                                    f"{name} source")
        output_hash = _check_sha256(e.output, e.output_manifest_sha256,
                                    f"{name} output")
        care_ranges = legacy.parse_ranges(record["ranges"],
                                          extent_blocks=sizes[0] // block_size)
        changed = _changed_blocks(
            e.source, e.output, sizes[0] // block_size, care_ranges, block_size
        )
        report.append({
            "name": name,
            "source_image_sha256": source_hash,
            "output_image_sha256": output_hash,
            "source_image_size": len(e.source),
            "output_image_size": len(e.output),
            "hashtree_image_size": sizes[0],
            "footer_original_image_size": sizes[0],
            "property_id": expected_id,
            "source_fingerprint": e.source_filesystem_fingerprint,
            "output_fingerprint": e.output_filesystem_fingerprint,
            "ranges": record["ranges"],
            "changed_protected_blocks": changed,
        })
    return {
        "schema": "modos-care-map-preservation-proof-v1",
        "source_care_map_sha256": source_care_map_sha256,
        "partitions": report,
        "candidate_care_map_matches_source_semantics": True,
        "note": "SYNTHETIC conditional proof only; signature and runtime attestations external",
    }
