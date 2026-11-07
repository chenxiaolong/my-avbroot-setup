# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Offline forensic extractor tests; never invoke real debugfs in CI."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import care_map_reference as reference
from tests import forensics_check_partition_props as check


SOURCE_FINGERPRINT = reference.witness()["source_fingerprint"]
AVB_FINGERPRINT = reference.witness()["avb_v3_34_1_fingerprint"]
PATHS = {
    "odm": "/etc/build.prop",
    "product": "/etc/build.prop",
    "system": "/system/build.prop",
    "system_ext": "/etc/build.prop",
    "vendor": "/build.prop",
    "vendor_dlkm": "/etc/build.prop",
}


class OriginalPropertyPathEvidenceTests(unittest.TestCase):
    def test_exact_six_original_build_prop_paths_from_signed_image_logs(self):
        actual = {
            p["name"]: p["original_filesystem_build_prop_path"]
            for p in reference.witness()["partitions"]
        }
        self.assertEqual(PATHS, actual)
        self.assertEqual(len(PATHS), len(reference.parse_map(reference.source_bytes())))

    def test_property_key_must_be_exact_not_global_or_prefix(self):
        data = (
            f"# ro.product.build.fingerprint={AVB_FINGERPRINT}\n"
            f"ro.build.fingerprint={AVB_FINGERPRINT}\n"
            f"ro.product.build.fingerprint.extra={AVB_FINGERPRINT}\n"
            f"ro.vendor.build.fingerprint={AVB_FINGERPRINT}\n"
            f"ro.product.build.fingerprint={SOURCE_FINGERPRINT}\n"
        ).encode()
        self.assertEqual(
            SOURCE_FINGERPRINT,
            check.strict_property_from_build_prop(data, "ro.product.build.fingerprint")
        )
        with self.assertRaisesRegex(ValueError, "missing/ambiguous"):
            check.strict_property_from_build_prop(
                b"ro.build.fingerprint=global\n", "ro.product.build.fingerprint"
            )

    def test_duplicate_missing_empty_control_and_non_utf8_fail_closed(self):
        prop = "ro.product.build.fingerprint"
        invalid = (
            b"",
            b"ro.product.build.fingerprint=\n",
            (f"{prop}={SOURCE_FINGERPRINT}\n{prop}={SOURCE_FINGERPRINT}\n").encode(),
            b"ro.product.build.fingerprint=invalid value\n",
            b"ro.product.build.fingerprint=x\x00y\n",
            b"ro.product.build.fingerprint=\xff\n",
        )
        for contents in invalid:
            with self.subTest(contents=repr(contents[:50])):
                with self.assertRaises(ValueError):
                    check.strict_property_from_build_prop(contents, prop)

    def test_reject_nonpartition_id(self):
        with self.assertRaises(ValueError):
            check.strict_property_from_build_prop(
                b"ro.product.build.fingerprint=a\n", "com.android.build.product.fingerprint"
            )

    def fake_signed_image_directory(self, root: Path):
        evidence = reference.witness()
        for p in evidence["partitions"]:
            data = b"deterministic-image-only:" + p["name"].encode()
            (root / f'{p["name"]}.img').write_bytes(data)
            p["payload_image_sha256"] = hashlib.sha256(data).hexdigest()
        return evidence

    def test_extractor_reads_all_six_hash_pinned_files_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness = self.fake_signed_image_directory(root)
            calls = []

            def fake_debugfs(argv, **kwargs):
                calls.append(argv)
                self.assertEqual("debugfs-readonly", argv[0])
                self.assertEqual("-R", argv[1])
                self.assertEqual("cat " + PATHS[Path(argv[-1]).stem], argv[2])
                self.assertEqual(root / f"{Path(argv[-1]).stem}.img", Path(argv[-1]))
                self.assertNotIn("shell", kwargs)
                return subprocess.CompletedProcess(
                    argv, 0, stdout=(
                        f"ro.{Path(argv[-1]).stem}.build.fingerprint="
                        f"{SOURCE_FINGERPRINT}\n"
                    ).encode(), stderr=b"debugfs tool banner"
                )

            with (
                mock.patch.object(check.reference, "witness", return_value=witness),
                mock.patch.object(check.subprocess, "run",
                                  side_effect=fake_debugfs) as runner,
            ):
                records = check.inspect_original_images(
                    root, debugfs_command="debugfs-readonly"
                )
            self.assertEqual(list(PATHS), [r["name"] for r in records])
            self.assertEqual(6, runner.call_count)
            self.assertTrue(all(r["fingerprint"] == SOURCE_FINGERPRINT
                                for r in records))

    def test_corrupt_image_digest_rejected_before_filesystem_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness = self.fake_signed_image_directory(root)
            (root / "odm.img").write_bytes(b"tampered original")
            with (
                mock.patch.object(check.reference, "witness", return_value=witness),
                mock.patch.object(check.subprocess, "run") as runner,
                self.assertRaisesRegex(ValueError, "signed-image SHA-256 mismatch"),
            ):
                check.inspect_original_images(root)
            runner.assert_not_called()

    def test_symlink_images_rejected_even_when_target_has_matching_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness = self.fake_signed_image_directory(root)
            (root / "odm.img").unlink()
            (root / "odm.img").symlink_to(root / "product.img")
            with (
                mock.patch.object(check.reference, "witness", return_value=witness),
                mock.patch.object(check.subprocess, "run") as runner,
                self.assertRaisesRegex(ValueError, "symbolic-link"),
            ):
                check.inspect_original_images(root)
            runner.assert_not_called()

    def test_debugfs_failures_and_avb_derived_property_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            witness = self.fake_signed_image_directory(root)
            for status, observed in ((1, SOURCE_FINGERPRINT),
                                     (0, AVB_FINGERPRINT)):
                with self.subTest(status=status, fingerprint=observed):
                    def fake_debugfs(argv, **kwargs):
                        return subprocess.CompletedProcess(
                            argv, status,
                            stdout=(f"ro.odm.build.fingerprint={observed}\n").encode(),
                            stderr=b""
                        )
                    with (
                        mock.patch.object(check.reference, "witness", return_value=witness),
                        mock.patch.object(check.subprocess, "run",
                                          side_effect=fake_debugfs),
                        self.assertRaises(ValueError),
                    ):
                        check.inspect_original_images(root)


if __name__ == "__main__":
    unittest.main()
