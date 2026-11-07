# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Opt-in Worklane 1 provenance-aware image-difference candidate contract.

The candidate MUST be an implementation-independent adapter, not an import of
the tests.care_map_provenance_reference reference oracle. The test vectors
carry synthetic bytes and synthetic manifest hashes; no real signing is
claimed or performed. Missing candidate SKIPS by default; with
CARE_MAP_PROVENANCE_REQUIRED=1 it is a hard ERROR.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
import json
import os
import shlex
import subprocess
import unittest

from tests import care_map_provenance_reference as proof
from tests.test_care_map_preservation import (
    AVB, NAMES, STOCK, changed_block, digest, replace_image, synthetic_case
)


def encode_candidate_request(case: dict) -> dict:
    values = {
        "schema": "modos-care-map-provenance-v1",
        "block_size": 4096,
        "source_care_map_b64": base64.b64encode(case["source_care_map"]).decode("ascii"),
        "candidate_output_care_map_b64": base64.b64encode(
            case["candidate_output_care_map"]
        ).decode("ascii"),
        "source_care_map_sha256": case["source_care_map_sha256"],
        "source_manifest_dynamic_partitions": list(case["source_manifest_partitions"]),
        "output_manifest_dynamic_partitions": list(case["output_manifest_partitions"]),
        "partitions": [],
    }
    for name in sorted(case["partitions"]):
        e = asdict(case["partitions"][name])
        e["name"] = name
        e["source_image_b64"] = base64.b64encode(e.pop("source")).decode("ascii")
        e["output_image_b64"] = base64.b64encode(e.pop("output")).decode("ascii")
        values["partitions"].append(e)
    return values


class PreservationCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        argv = os.environ.get("CARE_MAP_PROVENANCE_CMD", "").strip()
        if not argv:
            if os.environ.get("CARE_MAP_PROVENANCE_REQUIRED") == "1":
                raise AssertionError(
                    "mandatory provenance candidate missing: CARE_MAP_PROVENANCE_CMD"
                )
            raise unittest.SkipTest(
                "Worklane 1 provenance implementation not integrated; "
                "reference tests do not certify a production proof"
            )
        cls.argv = shlex.split(argv)
        if not cls.argv:
            raise AssertionError("empty provenance candidate command")

    def invoke(self, case: dict, *, valid=True):
        request = encode_candidate_request(case)
        result = subprocess.run(
            self.argv, input=json.dumps(request, separators=(",", ":")),
            capture_output=True, text=True, check=False, timeout=60
        )
        if not valid:
            self.assertNotEqual(0, result.returncode, result.stdout)
            return
        self.assertEqual(0, result.returncode, result.stderr[-2500:])
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"provenance candidate returned invalid JSON: {exc}")
        expected = proof.prove_preserved_ranges(**case)
        self.assertEqual(expected["source_care_map_sha256"],
                         response.get("source_care_map_sha256"))
        self.assertIs(response.get("candidate_care_map_matches_source_semantics"), True)
        observed = response.get("partitions")
        self.assertIsInstance(observed, list)
        self.assertEqual(len(NAMES), len(observed))
        for actual, want in zip(observed, expected["partitions"]):
            with self.subTest(partition=want["name"]):
                for key in (
                    "name", "source_image_sha256", "output_image_sha256",
                    "source_image_size", "output_image_size",
                    "hashtree_image_size", "footer_original_image_size",
                    "property_id", "source_fingerprint", "output_fingerprint",
                    "ranges", "changed_protected_blocks"
                ):
                    self.assertEqual(want[key], actual.get(key))

    def test_six_partition_clean_proof(self):
        self.invoke(synthetic_case())

    def test_in_range_changes_and_signed_suffix_allowed(self):
        case = synthetic_case()
        replace_image(case, "product", block=4)
        replace_image(case, "system_ext", block=6)
        replace_image(case, "vendor", block=8)
        self.invoke(case)

    def test_changed_protected_hole_rejected_with_valid_new_digest(self):
        case = synthetic_case()
        replace_image(case, "product", block=3)
        self.invoke(case, valid=False)

    def test_missing_signed_output_hash_rejected(self):
        case = synthetic_case()
        replace_image(case, "product", block=4, pin_digest=False)
        self.invoke(case, valid=False)

    def test_avb_only_fingerprint_substitution_rejected(self):
        case = synthetic_case()
        entry = case["partitions"]["odm"]
        from dataclasses import replace
        case["partitions"]["odm"] = replace(
            entry, output_filesystem_fingerprint=AVB
        )
        self.invoke(case, valid=False)

    def test_wrong_output_care_map_rejected(self):
        case = synthetic_case()
        from tests import care_map_reference as ref
        entries = list(ref.parse_map(case["source_care_map"]).values())
        entries[0] = dict(entries[0], ranges="2,0,6")
        case["candidate_output_care_map"] = ref.encode_map(entries)
        self.invoke(case, valid=False)

    def test_missing_partition_and_malformed_footer_rejected(self):
        case = synthetic_case()
        case["output_manifest_partitions"] = tuple(NAMES[:-1])
        self.invoke(case, valid=False)
        case = synthetic_case()
        from dataclasses import replace
        entry = case["partitions"]["vendor"]
        case["partitions"]["vendor"] = replace(
            entry, output_footer_original_size=entry.output_footer_original_size + 4096
        )
        self.invoke(case, valid=False)


if __name__ == "__main__":
    unittest.main()
