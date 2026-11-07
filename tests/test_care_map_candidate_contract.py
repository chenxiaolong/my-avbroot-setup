# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Opt-in Worklane 1 adapter contract (not counted as offline green evidence).

Set CARE_MAP_CANDIDATE_CMD to an executable argv command accepting one JSON
request on stdin, returning one JSON object on stdout. No shell is involved.
Set CARE_MAP_CONFORMANCE_REQUIRE_CANDIDATE=1 to fail if it is unavailable.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import unittest

from tests import care_map_reference as ref


class CandidateInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        command = os.environ.get("CARE_MAP_CANDIDATE_CMD", "").strip()
        if not command:
            if os.environ.get("CARE_MAP_CONFORMANCE_REQUIRE_CANDIDATE") == "1":
                raise AssertionError("mandatory candidate adapter absent: CARE_MAP_CANDIDATE_CMD")
            raise unittest.SkipTest(
                "Worklane 1 candidate not wired; reference-only tests are not integration proof"
            )
        cls.argv = shlex.split(command)
        if not cls.argv:
            raise AssertionError("empty candidate argv")

    def invoke(self, request: dict, *, valid=True):
        result = subprocess.run(
            self.argv, input=json.dumps(request, separators=(",", ":")),
            capture_output=True, text=True, timeout=40, check=False
        )
        if not valid:
            self.assertNotEqual(0, result.returncode, result.stdout)
            return
        self.assertEqual(0, result.returncode, result.stderr)
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"candidate did not return one JSON object: {exc}")
        self.assertEqual(ref.expected_output(request), output)

    def test_all_six_historical_sparse_models(self):
        witness = ref.witness()
        for partition in witness["partitions"]:
            with self.subTest(partition=partition["name"]):
                self.invoke(ref.request_for_partition(witness, partition))

    def test_all_six_unsparsed_contiguous_models(self):
        witness = ref.witness()
        for partition in witness["partitions"]:
            with self.subTest(partition=partition["name"]):
                self.invoke(ref.request_for_partition(witness, partition, sparse=False))

    def test_changed_filesystem_fingerprint_not_auto_substituted_from_avb(self):
        f = ref.witness()
        request = ref.request_for_partition(f, f["partitions"][0])
        request["filesystem_fingerprint"] = "test/output:fingerprint"
        self.invoke(request)
        request["filesystem_fingerprint"] = f["source_fingerprint"]
        request["avb_fingerprint"] = "test/other:avb-fingerprint"
        self.invoke(request)

    def test_malformed_and_overlapping_chunks_fail_closed(self):
        f = ref.witness()
        partition = f["partitions"][1]  # product: multiple sparse chunks
        for modification in ("bad-id", "overlap", "no-chunks",
                             "out-of-bounds", "no-fingerprint"):
            req = ref.request_for_partition(f, partition)
            if modification == "bad-id":
                req["filesystem_property_id"] = "ro.vendor.build.fingerprint"
            elif modification == "overlap":
                req["sparse_chunks"][1]["start"] -= 1
            elif modification == "no-chunks":
                req["sparse_chunks"] = []
            elif modification == "out-of-bounds":
                req["original_image_size"] += 4096 * 10
            else:
                req["filesystem_fingerprint"] = ""
            with self.subTest(modification=modification):
                self.invoke(req, valid=False)


if __name__ == "__main__":
    unittest.main()
