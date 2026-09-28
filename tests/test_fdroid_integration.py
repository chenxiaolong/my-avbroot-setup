# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""End-to-end fixture for the locked F-Droid image-patch boundary."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

from lib.filesystem import ExtEntry, ExtFs, ExtInfo
from lib.modules.catalog import load_catalog
from lib.modules.fdroid_privileged_extension import (
    CLIENT_ARTIFACT_ID,
    CLIENT_PATH,
    CLIENT_SOURCE_ARTIFACT_ID,
    FPE_PATH,
    FPE_SOURCE_ARTIFACT_ID,
    INJECTED_PATHS,
    OTA_ALLOWLIST,
    OTA_ARTIFACT_ID,
    PERMISSIONS_XML_PATH,
)
from lib.modules.locks import cache_path
from lib.modules.registry import locked_adapter_factories
from lib.modules.report import build_patch_report, write_patch_report
from lib.modules.verified import (
    construct_locked_adapters,
    open_verified_selection,
)
from tests import test_fdroid_provider as provider_fixture


MODULE_ID = "fdroid-privileged-extension"
HOOK_MEMBERS = frozenset(
    (
        "80-fdroid.sh",
        "META-INF/com/google/android/update-binary",
    )
)
SYSTEM_LABEL = "u:object_r:system_file:s0"


def _directory(path: str) -> ExtEntry:
    return ExtEntry(
        path=PurePosixPath(path),
        file_type="Directory",
        file_mode=0o755,
        uid=0,
        gid=0,
        xattrs={"security.selinux": f"{SYSTEM_LABEL}\0"},
    )


def _filesystem(root: Path) -> ExtFs:
    tree = root / "system-tree"
    for path in ("system/app", "system/priv-app", "system/etc/permissions"):
        (tree / path).mkdir(parents=True, exist_ok=True)
    return ExtFs(
        info=ExtInfo(
            metadata={
                "features": [],
                "block_size": 4096,
                "reserved_percentage": 0,
                "uuid": "00000000-0000-0000-0000-000000000000",
            },
            entries=[
                _directory("/"),
                _directory("/system"),
                _directory("/system/app"),
                _directory("/system/priv-app"),
                _directory("/system/etc"),
                _directory("/system/etc/permissions"),
            ],
        ),
        tree=tree,
        contexts=[(re.compile(r"/.*"), SYSTEM_LABEL)],
    )


class FDroidIntegrationTest(unittest.TestCase):
    def test_provider_lock_to_extfs_and_report_is_deterministic(self) -> None:
        fixture = provider_fixture.FDroidProviderTest(
            methodName="test_full_fixture_generates_canonical_lock_with_roles_and_members"
        )
        fixture.setUp()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            lock_path = root / "fdroid.lock.json"
            lock = fixture._generate_lock(lock_path)
            lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()

            payloads = {
                CLIENT_ARTIFACT_ID: fixture.client,
                CLIENT_SOURCE_ARTIFACT_ID: fixture.client_source,
                OTA_ARTIFACT_ID: fixture.ota,
                FPE_SOURCE_ARTIFACT_ID: fixture.fpe_source,
            }
            cache = root / "cache"
            for artifact in lock.modules[0].artifacts:
                cached = cache_path(cache, artifact.sha256)
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_bytes(payloads[artifact.id])
                cached.chmod(0o444)

            profile = root / "lineage-profile.toml"
            profile.write_text(
                f"""schema_version = 1
id = 'fdroid-full-boundary-fixture'
rom_family = 'lineageos'
root_mode = 'rootless'
abi = 'arm64-v8a'
api_level = 35
output_scope = 'local-unpublished'
enabled_modules = ['fdroid-privileged-extension']

[capabilities]
root_providers = []
zygisk_providers = []
selective_signature_spoofing = false
product_priv_app = false
custom_init_selinux = false

[[experimental_acknowledgements]]
module = 'fdroid-privileged-extension'
lock_sha256 = '{lock_sha256}'
output_scope = 'local-unpublished'
acknowledgement = 'I accept the F-Droid privileged-extension experimental policy for this exact artifact lock and output scope.'
""",
                encoding="UTF-8",
            )

            opened_during_construction: list[str] = []
            original_open = zipfile.ZipFile.open

            def tracked_open(
                archive: zipfile.ZipFile,
                name: str | zipfile.ZipInfo,
                *args,
                **kwargs,
            ):
                member = name.filename if isinstance(name, zipfile.ZipInfo) else name
                opened_during_construction.append(member)
                return original_open(archive, name, *args, **kwargs)

            with (
                mock.patch("lib.modules.verified.verify_apk_identity") as verify_apk,
                mock.patch.object(subprocess, "run") as arbitrary_process,
                open_verified_selection(
                    load_catalog(),
                    lock_path,
                    profile,
                    cache,
                ) as selection,
            ):
                with mock.patch.object(zipfile.ZipFile, "open", tracked_open):
                    adapters = construct_locked_adapters(
                        selection,
                        locked_adapter_factories(),
                    )

                self.assertEqual((MODULE_ID,), selection.resolution.selected_modules)
                self.assertEqual(2, verify_apk.call_count)
                self.assertEqual(list(OTA_ALLOWLIST), opened_during_construction)
                self.assertTrue(HOOK_MEMBERS.isdisjoint(opened_during_construction))

                filesystem = _filesystem(root)
                results = tuple(
                    (
                        module_id,
                        adapter.inject({}, {"system": filesystem}, ()),
                    )
                    for module_id, adapter in adapters
                )
                arbitrary_process.assert_not_called()

                report = build_patch_report(selection, results)
                repeated = build_patch_report(selection, results)
                self.assertEqual(report, repeated)
                self.assertEqual(
                    json.dumps(report, sort_keys=True, separators=(",", ":")),
                    json.dumps(repeated, sort_keys=True, separators=(",", ":")),
                )

                report_path = root / "patch-report.json"
                write_patch_report(report_path, report)
                first_report_bytes = report_path.read_bytes()
                write_patch_report(report_path, repeated)
                self.assertEqual(first_report_bytes, report_path.read_bytes())

            self.assertEqual(
                tuple((path, "created") for path in INJECTED_PATHS),
                results[0][1].path_statuses,
            )
            self.assertEqual(
                [
                    {"module": MODULE_ID, "path": path, "status": "created"}
                    for path in INJECTED_PATHS
                ],
                report["injected_paths"],
            )
            self.assertEqual(
                {
                    CLIENT_PATH: fixture.client,
                    FPE_PATH: fixture.fpe_apk,
                    PERMISSIONS_XML_PATH: fixture.permission_xml,
                },
                {
                    path: (filesystem.tree / path.removeprefix("/")).read_bytes()
                    for path in INJECTED_PATHS
                },
            )

            artifacts = {
                artifact["artifact"]: artifact for artifact in report["artifacts"]
            }
            self.assertEqual(set(payloads), set(artifacts))
            self.assertEqual(
                CLIENT_SOURCE_ARTIFACT_ID,
                artifacts[CLIENT_ARTIFACT_ID]["corresponding_source_artifact"],
            )
            self.assertEqual(
                FPE_SOURCE_ARTIFACT_ID,
                artifacts[OTA_ARTIFACT_ID]["corresponding_source_artifact"],
            )
            linked_artifacts = {
                CLIENT_ARTIFACT_ID,
                artifacts[CLIENT_ARTIFACT_ID]["corresponding_source_artifact"],
                OTA_ARTIFACT_ID,
                artifacts[OTA_ARTIFACT_ID]["corresponding_source_artifact"],
            }
            self.assertEqual(set(payloads), linked_artifacts)
            self.assertEqual(
                {"corresponding-source"},
                {
                    artifacts[artifact_id]["role"]
                    for artifact_id in (
                        CLIENT_SOURCE_ARTIFACT_ID,
                        FPE_SOURCE_ARTIFACT_ID,
                    )
                },
            )
            self.assertEqual(
                {("local-unpublished",)},
                {
                    tuple(artifact["allowed_output_scopes"])
                    for artifact in artifacts.values()
                },
            )
            self.assertEqual("local-unpublished", report["output_scope_policy"])
            self.assertEqual([], list(root.glob(".patch-report.json.*.tmp")))


if __name__ == "__main__":
    unittest.main()
