# SPDX-FileCopyrightText: 2026 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import os
import re
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from lib.filesystem import (
    EntryExists,
    ExtEntry,
    ExtFs,
    ExtInfo,
    ExtInstallError,
    ExtInstallRequest,
)


DEFAULT_LABEL = "u:object_r:system_file:s0"
APP_LABEL = "u:object_r:system_app_file:s0"


def directory_entry(
    path: str,
    *,
    mode: int = 0o755,
    uid: int = 0,
    gid: int = 0,
    label: str = DEFAULT_LABEL,
) -> ExtEntry:
    return ExtEntry(
        path=PurePosixPath(path),
        file_type="Directory",
        file_mode=mode,
        uid=uid,
        gid=gid,
        xattrs={"security.selinux": f"{label}\0"},
    )


def file_entry(
    path: str,
    *,
    mode: int = 0o644,
    uid: int = 0,
    gid: int = 0,
    label: str = APP_LABEL,
) -> ExtEntry:
    return ExtEntry(
        path=PurePosixPath(path),
        file_type="RegularFile",
        file_mode=mode,
        uid=uid,
        gid=gid,
        xattrs={"security.selinux": f"{label}\0"},
    )


class SafeFilesystemInstallTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tree = Path(self.temporary.name)
        (self.tree / "system").mkdir()
        self.fs = ExtFs(
            info=ExtInfo(
                metadata={
                    "features": [],
                    "block_size": 4096,
                    "reserved_percentage": 0,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                },
                entries=[directory_entry("/"), directory_entry("/system")],
            ),
            tree=self.tree,
            contexts=[
                (re.compile(r"/system/app(?:/.*)?"), APP_LABEL),
                (re.compile(r"/.*"), DEFAULT_LABEL),
            ],
        )

    @staticmethod
    def app_requests(data: bytes = b"apk") -> list[ExtInstallRequest]:
        # Deliberately put the child first to prove request order is irrelevant.
        return [
            ExtInstallRequest(
                "/system/app/F-Droid/F-Droid.apk",
                "RegularFile",
                0o644,
                0,
                0,
                data,
            ),
            ExtInstallRequest("/system/app", "Directory", 0o755, 0, 0),
            ExtInstallRequest("/system/app/F-Droid", "Directory", 0o755, 0, 0),
        ]

    def test_preflight_complete_batch_does_not_mutate(self) -> None:
        before_entries = list(self.fs.info.entries)

        results = self.fs.preflight_install(self.app_requests())

        self.assertEqual(
            [(str(result.path), result.status) for result in results],
            [
                ("/system/app", "created"),
                ("/system/app/F-Droid", "created"),
                ("/system/app/F-Droid/F-Droid.apk", "created"),
            ],
        )
        self.assertEqual(self.fs.info.entries, before_entries)
        self.assertFalse((self.tree / "system/app").exists())

    def test_install_creates_explicit_metadata_and_file_contents(self) -> None:
        results = self.fs.install(self.app_requests())

        self.assertEqual([result.status for result in results], ["created"] * 3)
        apk_path = self.tree / "system/app/F-Droid/F-Droid.apk"
        self.assertEqual(apk_path.read_bytes(), b"apk")
        entries = {str(entry.path): entry for entry in self.fs.info.entries}
        for path in (
            "/system/app",
            "/system/app/F-Droid",
            "/system/app/F-Droid/F-Droid.apk",
        ):
            self.assertEqual(entries[path].uid, 0)
            self.assertEqual(entries[path].gid, 0)
            self.assertEqual(
                entries[path].xattrs["security.selinux"],
                f"{APP_LABEL}\0",
            )
        self.assertEqual(entries["/system/app"].file_mode, 0o755)
        self.assertEqual(entries["/system/app/F-Droid/F-Droid.apk"].file_mode, 0o644)

    def test_reinstall_of_exact_batch_is_already_identical(self) -> None:
        self.fs.install(self.app_requests())
        entry_count = len(self.fs.info.entries)

        results = self.fs.install(self.app_requests())

        self.assertEqual(
            [result.status for result in results],
            ["already-identical"] * 3,
        )
        self.assertEqual(len(self.fs.info.entries), entry_count)

    def test_results_are_deterministic_across_request_order(self) -> None:
        forward = self.fs.preflight_install(self.app_requests())
        reverse = self.fs.preflight_install(reversed(self.app_requests()))

        self.assertEqual(forward, reverse)

    def test_paths_must_be_absolute_canonical_text(self) -> None:
        invalid = (
            "",
            "system/app",
            "/system//app",
            "/system/./app",
            "/system/app/",
            "//system/app",
            "/system/../vendor/app",
            "/system\\app",
            "/system/app\nname",
            b"/system/app",
        )
        for path in invalid:
            with self.subTest(path=path):
                request = ExtInstallRequest(
                    path,  # type: ignore[arg-type]
                    "Directory",
                    0o755,
                    0,
                    0,
                )
                with self.assertRaises(ExtInstallError):
                    self.fs.preflight_install([request])

    def test_duplicate_requests_are_rejected_before_mutation(self) -> None:
        request = ExtInstallRequest(
            "/system/duplicate",
            "RegularFile",
            0o644,
            0,
            0,
            b"data",
        )
        before_entries = list(self.fs.info.entries)

        with self.assertRaisesRegex(ExtInstallError, "duplicate installation path"):
            self.fs.install([request, request])

        self.assertEqual(self.fs.info.entries, before_entries)
        self.assertFalse((self.tree / "system/duplicate").exists())

    def test_collision_requires_all_file_properties_to_match(self) -> None:
        variants = {
            "bytes": ExtInstallRequest(
                "/system/existing.apk",
                "RegularFile",
                0o644,
                0,
                0,
                b"other",
            ),
            "mode": ExtInstallRequest(
                "/system/existing.apk",
                "RegularFile",
                0o600,
                0,
                0,
                b"apk",
            ),
            "uid": ExtInstallRequest(
                "/system/existing.apk",
                "RegularFile",
                0o644,
                1,
                0,
                b"apk",
            ),
            "gid": ExtInstallRequest(
                "/system/existing.apk",
                "RegularFile",
                0o644,
                0,
                1,
                b"apk",
            ),
        }
        for name, request in variants.items():
            with self.subTest(name=name):
                target = self.tree / "system/existing.apk"
                target.write_bytes(b"apk")
                entry = file_entry("/system/existing.apk", label=DEFAULT_LABEL)
                self.fs.info.entries.append(entry)
                with self.assertRaises(EntryExists):
                    self.fs.preflight_install([request])
                self.fs.info.entries.remove(entry)
                target.unlink()

    def test_collision_requires_matching_type_and_resolved_label(self) -> None:
        target = self.tree / "system/existing.apk"
        target.write_bytes(b"apk")
        wrong_label = file_entry("/system/existing.apk", label="u:object_r:wrong:s0")
        self.fs.info.entries.append(wrong_label)
        request = ExtInstallRequest(
            "/system/existing.apk",
            "RegularFile",
            0o644,
            0,
            0,
            b"apk",
        )
        with self.assertRaises(EntryExists):
            self.fs.preflight_install([request])

        self.fs.info.entries.remove(wrong_label)
        target.unlink()
        target.mkdir()
        self.fs.info.entries.append(directory_entry("/system/existing.apk"))
        with self.assertRaises(EntryExists):
            self.fs.preflight_install([request])

    def test_collision_rejects_unrequested_extra_xattrs(self) -> None:
        target = self.tree / "system/existing.apk"
        target.write_bytes(b"apk")
        entry = file_entry("/system/existing.apk", label=DEFAULT_LABEL)
        entry.xattrs["security.capability"] = "unexpected"
        self.fs.info.entries.append(entry)
        request = ExtInstallRequest(
            "/system/existing.apk",
            "RegularFile",
            0o644,
            0,
            0,
            b"apk",
        )

        with self.assertRaises(EntryExists):
            self.fs.preflight_install([request])

    def test_metadata_tree_disagreement_is_rejected(self) -> None:
        self.fs.info.entries.append(file_entry("/system/missing"))
        request = ExtInstallRequest(
            "/system/missing",
            "RegularFile",
            0o644,
            0,
            0,
            b"",
        )
        with self.assertRaisesRegex(ExtInstallError, "metadata/tree disagreement"):
            self.fs.preflight_install([request])

        self.fs.info.entries.pop()
        (self.tree / "system/orphan").write_bytes(b"")
        request = ExtInstallRequest(
            "/system/orphan",
            "RegularFile",
            0o644,
            0,
            0,
            b"",
        )
        with self.assertRaisesRegex(ExtInstallError, "metadata/tree disagreement"):
            self.fs.preflight_install([request])

    def test_duplicate_metadata_is_rejected(self) -> None:
        self.fs.info.entries.append(directory_entry("/system"))
        request = ExtInstallRequest(
            "/system/new",
            "RegularFile",
            0o644,
            0,
            0,
            b"",
        )

        with self.assertRaisesRegex(ExtInstallError, "duplicate filesystem metadata"):
            self.fs.preflight_install([request])

    def test_symlink_and_non_directory_parents_are_rejected(self) -> None:
        real = self.tree / "real"
        real.mkdir()
        link = self.tree / "system/link"
        link.symlink_to(real, target_is_directory=True)
        self.fs.info.entries.append(
            ExtEntry(
                path=PurePosixPath("/system/link"),
                file_type="Symlink",
                file_mode=0o777,
                uid=0,
                gid=0,
                symlink_target=str(real),
                xattrs={"security.selinux": f"{DEFAULT_LABEL}\0"},
            )
        )
        child = ExtInstallRequest(
            "/system/link/child",
            "RegularFile",
            0o644,
            0,
            0,
            b"",
        )
        with self.assertRaisesRegex(ExtInstallError, "parent is not a directory"):
            self.fs.preflight_install([child])

        self.fs.info.entries.pop()
        link.unlink()
        parent = self.tree / "system/parent"
        parent.write_bytes(b"")
        self.fs.info.entries.append(file_entry("/system/parent", label=DEFAULT_LABEL))
        child = ExtInstallRequest(
            "/system/parent/child",
            "RegularFile",
            0o644,
            0,
            0,
            b"",
        )
        with self.assertRaisesRegex(ExtInstallError, "parent is not a directory"):
            self.fs.preflight_install([child])

    def test_planned_parent_must_be_directory(self) -> None:
        requests = [
            ExtInstallRequest("/system/new", "RegularFile", 0o644, 0, 0, b""),
            ExtInstallRequest("/system/new/child", "RegularFile", 0o644, 0, 0, b""),
        ]
        with self.assertRaisesRegex(ExtInstallError, "planned installation parent"):
            self.fs.preflight_install(requests)

    def test_one_collision_prevents_every_mutation(self) -> None:
        existing_path = self.tree / "system/existing"
        existing_path.write_bytes(b"old")
        self.fs.info.entries.append(
            file_entry(
                "/system/existing",
                label=DEFAULT_LABEL,
            )
        )
        before_entries = list(self.fs.info.entries)
        requests = [
            ExtInstallRequest("/system/new", "RegularFile", 0o644, 0, 0, b"new"),
            ExtInstallRequest("/system/existing", "RegularFile", 0o644, 0, 0, b"new"),
        ]

        with self.assertRaises(EntryExists):
            self.fs.install(requests)

        self.assertFalse((self.tree / "system/new").exists())
        self.assertEqual(existing_path.read_bytes(), b"old")
        self.assertEqual(self.fs.info.entries, before_entries)

    def test_symlink_swap_after_preflight_cannot_escape_tree(self) -> None:
        outside = self.tree / "outside"
        outside.mkdir()
        held_system = self.tree / "held-system"
        original_preflight = self.fs._preflight_install

        def preflight_then_swap(requests):
            plan = original_preflight(requests)
            (self.tree / "system").rename(held_system)
            (self.tree / "system").symlink_to(outside, target_is_directory=True)
            return plan

        before_entries = list(self.fs.info.entries)
        with mock.patch.object(
            self.fs,
            "_preflight_install",
            side_effect=preflight_then_swap,
        ):
            with self.assertRaisesRegex(ExtInstallError, "parent changed or is unsafe"):
                self.fs.install(self.app_requests())

        self.assertFalse((outside / "app").exists())
        self.assertEqual(self.fs.info.entries, before_entries)

    def test_write_failure_rolls_back_complete_batch(self) -> None:
        before_entries = list(self.fs.info.entries)
        real_write = os.write
        writes = 0

        def fail_second_file(descriptor, data):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("injected write failure")
            return real_write(descriptor, data)

        requests = [
            ExtInstallRequest("/system/new", "Directory", 0o755, 0, 0),
            ExtInstallRequest(
                "/system/new/a",
                "RegularFile",
                0o644,
                0,
                0,
                b"a",
            ),
            ExtInstallRequest(
                "/system/new/b",
                "RegularFile",
                0o644,
                0,
                0,
                b"b",
            ),
        ]
        with mock.patch("lib.filesystem.os.write", side_effect=fail_second_file):
            with self.assertRaisesRegex(OSError, "injected write failure"):
                self.fs.install(requests)

        self.assertFalse((self.tree / "system/new").exists())
        self.assertEqual(self.fs.info.entries, before_entries)

    def test_legacy_open_behavior_is_preserved(self) -> None:
        with self.fs.open("/system/legacy", "wb", mode=0o600) as output:
            output.write(b"legacy")  # type: ignore[arg-type]

        self.assertEqual((self.tree / "system/legacy").read_bytes(), b"legacy")
        entry = next(
            entry
            for entry in self.fs.info.entries
            if entry.path == PurePosixPath("/system/legacy")
        )
        self.assertEqual(entry.file_mode, 0o600)


if __name__ == "__main__":
    unittest.main()
