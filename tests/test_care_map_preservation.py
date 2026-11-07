# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Offline independent regression vectors for Worklane 1's proposed D subset S.

All image buffers are deterministic synthetic data. Their hash fields imitate
a *separately authenticated* signed manifest; this cannot validate a signature,
real ext4/debugfs, actual AVB metadata, or first-boot update_verifier.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest

from tests import care_map_reference as ref
from tests import care_map_provenance_reference as proof


NAMES = ("odm", "product", "system", "system_ext", "vendor", "vendor_dlkm")
RANGES = {
    "odm": "2,0,8",
    "product": "4,0,2,4,7",
    "system": "4,0,3,5,8",
    "system_ext": "4,0,2,6,8",
    "vendor": "2,0,8",
    "vendor_dlkm": "2,0,8",
}
BLOCK_SIZE = 4096
DATA_BLOCKS = 8
WHOLE_BLOCKS = 10
FS_BYTES = BLOCK_SIZE * DATA_BLOCKS
STOCK = ref.witness()["source_fingerprint"]
AVB = ref.witness()["avb_v3_34_1_fingerprint"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def synthetic_image(partition_number: int):
    return b"".join(
        bytes([(partition_number * 19 + block * 7 + 1) % 256]) * BLOCK_SIZE
        for block in range(WHOLE_BLOCKS)
    )


def synthetic_evidence(partition_number: int, name: str):
    image = synthetic_image(partition_number)
    return proof.ImageEvidence(
        source=image, output=image,
        source_manifest_sha256=digest(image),
        output_manifest_sha256=digest(image),
        source_manifest_size=len(image),
        output_manifest_size=len(image),
        source_footer_original_size=FS_BYTES,
        output_footer_original_size=FS_BYTES,
        source_hashtree_image_size=FS_BYTES,
        output_hashtree_image_size=FS_BYTES,
        source_property_id=f"ro.{name}.build.fingerprint",
        output_property_id=f"ro.{name}.build.fingerprint",
        source_filesystem_fingerprint=STOCK,
        output_filesystem_fingerprint=STOCK,
    )


def synthetic_case():
    """Provide six fake partitions, not the original authenticated image bytes."""
    proto = ref.encode_map([
        {
            "name": name,
            "ranges": RANGES[name],
            "id": f"ro.{name}.build.fingerprint",
            "fingerprint": STOCK,
        } for name in NAMES
    ])
    return {
        "source_care_map": proto,
        "candidate_output_care_map": proto,
        "source_care_map_sha256": digest(proto),
        "source_manifest_partitions": tuple(NAMES),
        "output_manifest_partitions": tuple(NAMES),
        "partitions": {
            name: synthetic_evidence(i, name)
            for i, name in enumerate(NAMES)
        },
    }


def changed_block(image: bytes, block: int, value: int = 0xc7) -> bytes:
    mutable = bytearray(image)
    mutable[block * BLOCK_SIZE + 97] ^= value
    return bytes(mutable)


def replace_image(testcase: dict, name: str, *, block: int,
                  source_change: bool = False, pin_digest: bool = True):
    old = testcase["partitions"][name]
    if source_change:
        updated = changed_block(old.source, block)
        testcase["partitions"][name] = replace(
            old, source=updated,
            source_manifest_sha256=digest(updated)
            if pin_digest else old.source_manifest_sha256
        )
    else:
        updated = changed_block(old.output, block)
        testcase["partitions"][name] = replace(
            old, output=updated,
            output_manifest_sha256=digest(updated)
            if pin_digest else old.output_manifest_sha256
        )


def run(case: dict):
    return proof.prove_preserved_ranges(**case)


class PreservationProofReferenceTests(unittest.TestCase):
    def assert_rejected(self, case: dict, text: str):
        with self.assertRaisesRegex(ValueError, text):
            run(case)

    def test_six_partition_clean_copy_passes(self):
        result = run(synthetic_case())
        self.assertEqual("modos-care-map-preservation-proof-v1", result["schema"])
        self.assertTrue(result["candidate_care_map_matches_source_semantics"])
        self.assertEqual(list(NAMES), [r["name"] for r in result["partitions"]])
        self.assertEqual([0] * 6,
                         [r["changed_protected_blocks"] for r in result["partitions"]])
        self.assertEqual([RANGES[name] for name in NAMES],
                         [r["ranges"] for r in result["partitions"]])

    def test_each_cared_partition_can_change_selected_blocks(self):
        case = synthetic_case()
        selected = {"odm": 0, "product": 4, "system": 6,
                    "system_ext": 6, "vendor": 7, "vendor_dlkm": 2}
        for name, block in selected.items():
            replace_image(case, name, block=block)
        report = run(case)
        self.assertEqual([1] * 6,
                         [r["changed_protected_blocks"] for r in report["partitions"]])

    def test_protected_uncared_holes_cannot_be_changed(self):
        for name, block in (("product", 2), ("product", 3),
                            ("product", 7), ("system", 3),
                            ("system_ext", 2), ("system_ext", 5)):
            with self.subTest(partition=name, block=block):
                case = synthetic_case()
                replace_image(case, name, block=block)
                self.assert_rejected(
                    case, f"protected block {block} changed outside authenticated"
                )

    def test_signed_manifest_aware_suffix_changes_are_not_data_block_changes(self):
        case = synthetic_case()
        replace_image(case, "product", block=8)
        replace_image(case, "vendor", block=9)
        result = run(case)
        self.assertEqual([0] * 6,
                         [r["changed_protected_blocks"] for r in result["partitions"]])
        self.assertNotEqual(
            case["partitions"]["product"].source_manifest_sha256,
            case["partitions"]["product"].output_manifest_sha256
        )

    def test_change_inside_cared_range_without_signed_digest_update_rejected(self):
        case = synthetic_case()
        replace_image(case, "product", block=4, pin_digest=False)
        self.assert_rejected(case, "output: image SHA-256 not bound")

    def test_change_outside_protected_data_without_digest_update_rejected(self):
        case = synthetic_case()
        replace_image(case, "vendor", block=9, pin_digest=False)
        self.assert_rejected(case, "output: image SHA-256 not bound")

    def test_source_digest_must_match_an_authenticated_manifest(self):
        case = synthetic_case()
        replace_image(case, "product", block=4, source_change=True, pin_digest=False)
        self.assert_rejected(case, "source: image SHA-256 not bound")

    def test_changed_source_with_relabelled_manifest_hash_is_still_compared(self):
        case = synthetic_case()
        replace_image(case, "product", block=3, source_change=True)
        self.assert_rejected(case, "protected block 3 changed outside authenticated")

    def test_cared_change_detects_exact_block_count(self):
        case = synthetic_case()
        replace_image(case, "product", block=4)
        first = case["partitions"]["product"]
        updated = changed_block(first.output, 5)
        case["partitions"]["product"] = replace(
            first, output=updated, output_manifest_sha256=digest(updated)
        )
        report = run(case)
        self.assertEqual(2, report["partitions"][1]["changed_protected_blocks"])

    def test_source_care_map_sha_and_malformed_source_are_checked(self):
        case = synthetic_case()
        case["source_care_map_sha256"] = "a" * 64
        self.assert_rejected(case, "source care-map: image SHA-256 not bound")
        case = synthetic_case()
        case["source_care_map"] = case["source_care_map"][:-1]
        case["source_care_map_sha256"] = digest(case["source_care_map"])
        self.assert_rejected(case, "truncated protobuf")

    def test_output_care_map_mutation_all_fingerprint_id_range_rejected(self):
        for change in ("avb-fingerprint", "change-id", "expand-range",
                       "narrow-range", "remove", "add", "duplicate", "truncate"):
            with self.subTest(change=change):
                case = synthetic_case()
                entries = list(ref.parse_map(case["source_care_map"]).values())
                if change == "avb-fingerprint":
                    entries[1] = dict(entries[1], fingerprint=AVB)
                elif change == "change-id":
                    entries[1] = dict(entries[1], id="ro.vendor.build.fingerprint")
                elif change == "expand-range":
                    entries[1] = dict(entries[1], ranges="2,0,8")
                elif change == "narrow-range":
                    entries[1] = dict(entries[1], ranges="2,0,2")
                elif change == "remove":
                    entries.pop()
                elif change == "add":
                    entries.append({
                        "name": "extra", "ranges": "2,0,8",
                        "id": "ro.extra.build.fingerprint", "fingerprint": STOCK,
                    })
                elif change == "duplicate":
                    entries.append(entries[0])
                if change == "truncate":
                    case["candidate_output_care_map"] = case["candidate_output_care_map"][:-2]
                else:
                    case["candidate_output_care_map"] = ref.encode_map(entries)
                self.assert_rejected(case, "candidate care-map|property ID|duplicate|truncated")

    def test_record_order_alone_does_not_change_semantic_partition_set(self):
        case = synthetic_case()
        records = list(ref.parse_map(case["source_care_map"]).values())
        case["candidate_output_care_map"] = ref.encode_map(list(reversed(records)))
        self.assertTrue(run(case)["candidate_care_map_matches_source_semantics"])

    def test_unknown_missing_and_duplicate_manifest_partitions_rejected(self):
        cases = [
            (tuple(NAMES[:-1]), tuple(NAMES)),
            (tuple(NAMES), tuple(NAMES[:-1])),
            (tuple(NAMES) + ("extra",), tuple(NAMES)),
            (tuple(NAMES) + ("odm",), tuple(NAMES)),
            (tuple(NAMES), tuple(NAMES) + ("odm",)),
            ((), tuple(NAMES)),
        ]
        for source, final in cases:
            with self.subTest(source=source, final=final):
                case = synthetic_case()
                case["source_manifest_partitions"] = source
                case["output_manifest_partitions"] = final
                self.assert_rejected(case, "partition|manifest")
        case = synthetic_case()
        del case["partitions"]["system"]
        self.assert_rejected(case, "partition|manifest")

    def test_manifest_missing_hash_size_and_wrong_image_layout_fail_closed(self):
        for update in (
            {"source_manifest_sha256": ""},
            {"source_manifest_sha256": "not_a_digest"},
            {"output_manifest_sha256": None},
            {"source_manifest_size": 4096},
            {"output_manifest_size": WHOLE_BLOCKS * BLOCK_SIZE + 1},
            {"output_footer_original_size": FS_BYTES + BLOCK_SIZE},
            {"source_footer_original_size": 0},
            {"source_hashtree_image_size": FS_BYTES - BLOCK_SIZE},
            {"output_hashtree_image_size": FS_BYTES + BLOCK_SIZE},
            {"output_footer_original_size": FS_BYTES - 1},
        ):
            with self.subTest(update=update):
                case = synthetic_case()
                case["partitions"]["system"] = replace(
                    case["partitions"]["system"], **update
                )
                self.assert_rejected(case, "digest|size|extent|layout|protected")

    def test_missing_or_wrong_final_runtime_fingerprint_rejected(self):
        for replacement in (None, "", AVB, "some-other-build:fingerprint"):
            with self.subTest(replacement=replacement):
                case = synthetic_case()
                case["partitions"]["system_ext"] = replace(
                    case["partitions"]["system_ext"],
                    output_filesystem_fingerprint=replacement
                )
                self.assert_rejected(case, "filesystem fingerprint drift")

    def test_wrong_source_runtime_fingerprint_rejected(self):
        case = synthetic_case()
        case["partitions"]["odm"] = replace(
            case["partitions"]["odm"],
            source_filesystem_fingerprint=AVB
        )
        self.assert_rejected(case, "filesystem fingerprint drift")

    def test_missing_or_wrong_source_or_output_property_id_rejected(self):
        for side in ("source", "output"):
            for candidate in (None, "", "ro.vendor.build.fingerprint"):
                with self.subTest(side=side, candidate=candidate):
                    case = synthetic_case()
                    case["partitions"]["product"] = replace(
                        case["partitions"]["product"],
                        **{f"{side}_property_id": candidate}
                    )
                    self.assert_rejected(case, "filesystem property ID")

    def test_non_ext4_output_source_fail_closed(self):
        for side in ("source", "output"):
            case = synthetic_case()
            case["partitions"]["vendor_dlkm"] = replace(
                case["partitions"]["vendor_dlkm"],
                **{f"{side}_filesystem_type": "erofs"}
            )
            self.assert_rejected(case, "unsupported filesystem")

    def test_same_data_length_and_whole_signed_manifest_length_required(self):
        case = synthetic_case()
        entry = case["partitions"]["odm"]
        shortened = entry.output[:-1]
        case["partitions"]["odm"] = replace(
            entry, output=shortened, output_manifest_sha256=digest(shortened),
            output_manifest_size=len(shortened)
        )
        self.assert_rejected(case, "whole-image layout or size drift")

    def test_zero_data_outside_care_does_not_make_a_changed_hole_safe(self):
        case = synthetic_case()
        entry = case["partitions"]["product"]
        block3 = bytearray(entry.output)
        block3[BLOCK_SIZE * 3:BLOCK_SIZE * 4] = b"\0" * BLOCK_SIZE
        output = bytes(block3)
        case["partitions"]["product"] = replace(
            entry, output=output, output_manifest_sha256=digest(output)
        )
        self.assert_rejected(case, "protected block 3 changed outside")

    def test_reference_report_does_not_claim_cryptographic_authentication(self):
        result = run(synthetic_case())
        self.assertIn("SYNTHETIC conditional proof", result["note"])
        self.assertNotIn("publisher_signature_verified", result)
        self.assertNotIn("first_boot_verified", result)


class HistoricalCareMapExtentBoundaryTests(unittest.TestCase):
    """Validate original pdx235 half-open endpoints without giant images.

    This validates membership and range encoding, NOT provenance of block
    change locations, which requires real manifest-authenticated image bytes.
    """

    def test_all_historical_source_endpoints_are_half_open(self):
        f = ref.witness()
        for p in f["partitions"]:
            bound = ref.parse_ranges(p["avb_v3_34_1_ranges"])[0][1]
            ranges = ref.parse_ranges(p["source_ranges"], extent_blocks=bound)
            with self.subTest(partition=p["name"]):
                self.assertEqual(p["source_ranges"], ref.raw_ranges(ranges))
                self.assertEqual(0, ranges[0][0])
                for start, end in ranges:
                    self.assertTrue(any(a <= start < b for a, b in ranges))
                    self.assertTrue(any(a <= end - 1 < b for a, b in ranges))
                    self.assertFalse(any(a <= end < b for a, b in ranges))
                self.assertFalse(any(a <= bound < b for a, b in ranges))

    def test_actual_high_sparse_ranges_must_not_be_expanded_to_contiguous(self):
        witness = ref.witness()
        partitions = {p["name"]: p for p in witness["partitions"]}
        # End is exclusive: product block 589824 is selected; 589825 is not.
        samples = (("product", 589824, 589825),
                   ("system", 262144, 262145),
                   ("system_ext", 131072, 131073))
        for name, inside, outside in samples:
            with self.subTest(partition=name):
                spans = ref.parse_ranges(partitions[name]["source_ranges"])
                self.assertTrue(any(s <= inside < e for s, e in spans))
                self.assertFalse(any(s <= outside < e for s, e in spans))
                avb_extent = ref.parse_ranges(
                    partitions[name]["avb_v3_34_1_ranges"]
                )[0][1]
                self.assertLess(outside, avb_extent)


if __name__ == "__main__":
    unittest.main()
