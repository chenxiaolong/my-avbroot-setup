# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Offline historical evidence, AOSP range reference, and real helper wiring.

These tests NEVER claim to have run avbroot against the full signed OTA.
Only external.verify_ota and local key encoding are mocked in integration
tests; the real care_map_compat parser and identity guard are exercised.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import hashlib
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from lib import care_map_compat, external
import patch as helper
from tests import care_map_reference as ref


def source_records():
    return ref.parse_map(ref.source_bytes())


class HistoricalWitnessTests(unittest.TestCase):
    def test_byte_exact_authenticated_original_care_map(self):
        f = ref.witness()
        self.assertEqual(
            hashlib.sha256(ref.source_bytes()).hexdigest(), f["care_map_sha256"]
        )
        self.assertEqual(1086, len(ref.source_bytes()))
        records = source_records()
        self.assertEqual(
            ["odm", "product", "system", "system_ext", "vendor", "vendor_dlkm"],
            list(records)
        )
        self.assertEqual(
            ref.encode_map([records[p["name"]] for p in f["partitions"]]),
            ref.source_bytes()
        )
        for part in f["partitions"]:
            name = part["name"]
            self.assertEqual(part["source_ranges"], records[name]["ranges"])
            self.assertEqual(f"ro.{name}.build.fingerprint", records[name]["id"])
            self.assertEqual(f["source_fingerprint"], records[name]["fingerprint"])

    def test_source_ranges_obey_avb_original_filesystem_bounds(self):
        f = ref.witness()
        bounds = {
            p["name"]: ref.parse_ranges(p["avb_v3_34_1_ranges"])[0][1]
            for p in f["partitions"]
        }
        self.assertEqual(set(bounds), set(ref.parse_map(ref.source_bytes(), limits=bounds)))
        for name, bound in bounds.items():
            self.assertLessEqual(
                ref.parse_ranges(source_records()[name]["ranges"])[-1][1], bound
            )

    def test_reconstructed_aosp_sparse_model_yields_byte_exact_source(self):
        f = ref.witness()
        # Synthetic chunks generated from the archived sparse ranges, NOT
        # independently recovered signed ext4/sparse chunk headers.
        records = [ref.expected_output(ref.request_for_partition(f, p))
                   for p in f["partitions"]]
        self.assertEqual(ref.source_bytes(), ref.encode_map(records))

    def test_avbroot_3_34_1_reference_reproduces_reported_mismatch(self):
        f = ref.witness()
        original = source_records()
        computed = {}
        for p in f["partitions"]:
            name = p["name"]
            # Independent reproduction of v3.34.1 care_map.rs, with image
            # extents and AVB properties witnessed by the 2026-10-09 CI log.
            req = ref.request_for_partition(f, p, sparse=False)
            result = ref.expected_output(req)
            computed[name] = dict(result, fingerprint=f["avb_v3_34_1_fingerprint"])
            self.assertEqual(p["avb_v3_34_1_ranges"], result["ranges"])
            self.assertNotEqual(computed[name]["fingerprint"], original[name]["fingerprint"])
        self.assertEqual({"product", "system", "system_ext"}, {
            name for name in original if original[name]["ranges"] != computed[name]["ranges"]
        })
        self.assertNotEqual(ref.encode_map(list(computed.values())), ref.source_bytes())
        # This mismatch is metadata-generation disagreement, NOT evidence of
        # corrupt bytes; independent source signature/hash attest separately.

    def test_fingerprint_runtime_property_is_not_avb_property(self):
        f = ref.witness()
        original = source_records()
        source_props = {
            f"ro.{p['name']}.build.fingerprint": f["source_fingerprint"]
            for p in f["partitions"]
        }
        self.assertEqual(set(original), ref.runtime_selected(original, source_props))
        bad = {name: dict(record, fingerprint=f["avb_v3_34_1_fingerprint"])
               for name, record in original.items()}
        self.assertEqual(set(), ref.runtime_selected(bad, source_props))
        self.assertEqual(set(), ref.runtime_selected(original, {}))

    def test_output_fingerprint_change_requires_real_output_filesystem_evidence(self):
        f = ref.witness()
        req = ref.request_for_partition(f, f["partitions"][0])
        self.assertEqual(f["source_fingerprint"], ref.expected_output(req)["fingerprint"])
        req["filesystem_fingerprint"] = f["avb_v3_34_1_fingerprint"]
        self.assertEqual(f["avb_v3_34_1_fingerprint"], ref.expected_output(req)["fingerprint"])
        self.assertNotEqual(
            ref.expected_output(req)["fingerprint"],
            source_records()["odm"]["fingerprint"]
        )

    def test_reordered_partitions_can_normalize_without_identity_changes(self):
        records = list(source_records().values())
        reversed_pb = ref.encode_map(list(reversed(records)))
        self.assertEqual(source_records(), ref.parse_map(reversed_pb))
        self.assertNotEqual(reversed_pb, ref.source_bytes())

    def test_fixture_tampering_cannot_become_a_green_source_witness(self):
        altered = bytearray(ref.source_bytes())
        altered[-1] ^= 1
        self.assertNotEqual(ref.witness()["care_map_sha256"],
                            hashlib.sha256(altered).hexdigest())


class RangeOracleTests(unittest.TestCase):
    def test_raw_fill_and_dontcare_with_adjacent_ranges(self):
        chunks = [
            {"type": "raw", "start": 0, "end": 2},
            {"type": "dontcare", "start": 2, "end": 4},
            {"type": "fill", "start": 4, "end": 6},
            {"type": "raw", "start": 6, "end": 8},
            {"type": "dontcare", "start": 8, "end": 10},
        ]
        self.assertEqual("4,0,2,4,8",
                         ref.sparse_ranges(chunks, total_blocks=10, image_size=8*4096))
        self.assertEqual("2,0,8", ref.contiguous_ranges(original_image_size=8*4096))

    def test_intersect_with_original_filesystem_not_appended_hashtree(self):
        chunks = [{"type": "raw", "start": 0, "end": 9}]
        self.assertEqual("2,0,3",
                         ref.sparse_ranges(chunks, total_blocks=9, image_size=3*4096))

    def test_non_sparsed_image_is_contiguous(self):
        f = ref.witness()
        for part in f["partitions"]:
            req = ref.request_for_partition(f, part, sparse=False)
            self.assertEqual(part["avb_v3_34_1_ranges"], ref.expected_output(req)["ranges"])
            self.assertEqual(f["source_fingerprint"],
                             ref.expected_output(req)["fingerprint"])

    def test_normalization_merges_adjacent_sorts_unordered(self):
        self.assertEqual(((0, 6), (10, 13)), ref.normalize(
            [(10, 11), (3, 6), (0, 3), (11, 13)], bound=15
        ))
        self.assertEqual("4,0,6,10,13", ref.raw_ranges(((0, 6), (10, 13))))

    def test_holes_remain_holes(self):
        self.assertEqual(((0, 2), (4, 7)), ref.normalize(
            [(4, 7), (0, 2)], bound=10
        ))

    def test_bad_extents_rejected(self):
        for spans, bound in (
            ([(0, 3), (2, 5)], 10), ([(0, 0)], 10), ([(3, 2)], 10),
            ([(-1, 2)], 10), ([(0, 11)], 10), ([], 10),
            ([(0, 1)], 0), ([(0, 1)], 1 << 64),
        ):
            with self.subTest(spans=spans, bound=bound):
                with self.assertRaises(ValueError):
                    ref.normalize(spans, bound=bound)

    def test_bad_sparse_chunk_order_holes_and_bounds_rejected(self):
        valid = [
            {"type": "raw", "start": 0, "end": 3},
            {"type": "dontcare", "start": 3, "end": 6},
        ]
        for chunks in (
            valid[:1],
            [valid[0], {"type": "fill", "start": 2, "end": 6}],
            [{"type": "raw", "start": 1, "end": 6}],
            [{"type": "raw", "start": 0, "end": 7}],
            [{"type": "crc32", "start": 0, "end": 6}],
        ):
            with self.subTest(chunks=chunks):
                with self.assertRaises(ValueError):
                    ref.sparse_ranges(chunks, total_blocks=6, image_size=4*4096)

    def test_empty_meaningful_sparse_blocks_rejected(self):
        with self.assertRaises(ValueError):
            ref.sparse_ranges(
                [{"type": "dontcare", "start": 0, "end": 4}],
                total_blocks=4, image_size=4*4096
            )

    def test_unaligned_and_out_of_bounds_image_size_rejected(self):
        for size in (0, -4096, 4097, 5*4096):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    ref.sparse_ranges(
                        [{"type": "raw", "start": 0, "end": 4}],
                        total_blocks=4, image_size=size
                    )
        with self.assertRaises(ValueError):
            ref.contiguous_ranges(original_image_size=4100)

    def test_range_decoding_positive_and_negative(self):
        self.assertEqual(((0, 2), (2, 8)), ref.parse_ranges("4,0,2,2,8"))
        for malformed in (
            "", "0", "2,0,0", "2,5,3", "4,0,5,3,8", "3,0,2,4",
            "2,0", "2,00,1", "2,+0,1", "2,-1,1", "2,0,1,",
            "2,0,9223372036854775809", "2,0,4\n",
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    ref.parse_ranges(malformed)
        with self.assertRaises(ValueError):
            ref.parse_ranges("2,0,11", extent_blocks=10)

    def test_duplicate_proto_partition_or_field_rejected(self):
        original = list(source_records().values())
        for data in (
            ref.encode_map([original[0], original[0]]),
            ref._field(1, b"".join(
                ref._field(i, original[0][key])
                for i, key in enumerate(("name", "ranges", "id", "fingerprint"), 1)
            ) + ref._field(4, original[0]["fingerprint"])),
            ref.encode_map([dict(original[0], id="ro.vendor.build.fingerprint")]),
            ref.encode_map([dict(original[0], name="INVALID")]),
            ref.encode_map([dict(original[0], fingerprint="")]),
            ref.encode_map([dict(original[0], ranges="4,0,2,1,4")]),
            ref.encode_map([dict(original[0], ranges="2,0,999999999")]),
        ):
            with self.subTest(data_length=len(data)):
                with self.assertRaises(ValueError):
                    ref.parse_map(data, limits={"odm": 472})

    def test_truncation_unknown_fields_and_oversize_rejected(self):
        sample = ref.source_bytes()
        for data in (
            sample[:-1], b"\x0a\xff\xff", b"\x00",
            sample + ref._field(2, b"unexpected"),
            ref._field(1, b"x" * 8193),
            b"x" * (1024 * 1024 + 1),
            b"",
        ):
            with self.subTest(data_len=len(data)):
                with self.assertRaises(ValueError):
                    ref.parse_map(data)

    def test_missing_field_unsupported_wire_type_and_duplicate_byte_names(self):
        record = source_records()["odm"]
        for data in (
            ref._field(1, ref._field(1, "odm")),
            b"\x08\x01",
            ref.encode_map([record, dict(record)]),
        ):
            with self.assertRaises(ValueError):
                ref.parse_map(data)

    def test_change_property_id_is_not_fingerprint_substitution(self):
        rec = dict(source_records()["odm"], id="ro.vendor.build.fingerprint")
        with self.assertRaisesRegex(ValueError, "property ID"):
            ref.parse_map(ref.encode_map([rec]))
        rec = dict(source_records()["odm"], fingerprint=ref.witness()["avb_v3_34_1_fingerprint"])
        parsed = ref.parse_map(ref.encode_map([rec]))
        self.assertEqual(rec["fingerprint"], parsed["odm"]["fingerprint"])
        self.assertNotIn("odm", ref.runtime_selected(parsed, {
            "ro.odm.build.fingerprint": ref.witness()["source_fingerprint"]
        }))


if __name__ == "__main__":
    unittest.main()
