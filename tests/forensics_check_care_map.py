# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Optional *read-only*, offline full-OTA forensic check. NEVER used by normal CI.

The original 1.23 GB OTA and independently pinned publisher key stay local.
No signing, patching, uploading, download, workflow, or output ZIP occurs.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import zipfile

from tests import care_map_reference as ref

VERIFIER_COMMIT = "9ffcf56a0fe152467da2971f0e6b2b79a42f7890"


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ota", type=Path, required=True)
    parser.add_argument("--lineageos-pubkey", type=Path)
    parser.add_argument("--lineageos-update-verifier", type=Path)
    parser.add_argument("--avbroot", type=Path)
    parser.add_argument("--avb-pkmd", type=Path)
    parser.add_argument("--ota-cert", type=Path)
    args = parser.parse_args(argv)

    f = ref.witness()
    if not args.ota.is_file() or args.ota.stat().st_size != f["ota_size_bytes"]:
        parser.error("wrong OTA size or absent file")
    if sha256_file(args.ota) != f["ota_sha256"]:
        parser.error("OTA SHA-256 differs from independently authenticated release")

    with zipfile.ZipFile(args.ota) as archive:
        matches = [i for i in archive.infolist() if i.filename == "care_map.pb"]
        if len(matches) != 1 or matches[0].is_dir() or matches[0].file_size > 1048576:
            parser.error("source care map missing/duplicate/unbounded")
        content = archive.read(matches[0])
    if content != ref.source_bytes():
        parser.error("source care_map.pb differs from byte-exact signed fixture")
    print("PASS: independently pinned OTA size, SHA-256, and embedded care_map.pb")

    # Require BOTH independent LineageOS key and pinned official verifier for
    # publisher signature validation; do not infer it from the OTA's own cert.
    publisher_supplied = (
        args.lineageos_pubkey is not None or
        args.lineageos_update_verifier is not None
    )
    if publisher_supplied:
        if not (args.lineageos_pubkey and args.lineageos_update_verifier):
            parser.error("publisher verification requires BOTH key and verifier")
        if sha256_file(args.lineageos_pubkey) != f["lineageos_pubkey_pem_sha256"]:
            parser.error("LineageOS PEM key does not match pinned independent key")
        script = args.lineageos_update_verifier
        git = subprocess.run(
            ["git", "-C", str(script.parent), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=False, timeout=15
        )
        if git.returncode != 0 or git.stdout.strip() != VERIFIER_COMMIT:
            parser.error("update_verifier checkout is not the reviewed pinned commit")
        checked = subprocess.run(
            [sys.executable, str(script), str(args.lineageos_pubkey), str(args.ota)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False, timeout=2400
        )
        if checked.returncode != 0:
            raise RuntimeError(
                f"independent LineageOS publisher signature FAILED: {checked.stdout[-2000:]}"
            )
        print("PASS: independent publisher verification against pinned LineageOS key")

    external_supplied = any((args.avbroot, args.avb_pkmd, args.ota_cert))
    if external_supplied:
        if not all((args.avbroot, args.avb_pkmd, args.ota_cert)):
            parser.error("avbroot evidence requires --avbroot, --avb-pkmd and --ota-cert")
        if not publisher_supplied:
            parser.error("run independent publisher verification BEFORE avbroot evidence")
        # These supplied identities are used to exercise avbroot's AVB/OTA
        # internal checks after authentication, NOT as a publisher trust root.
        version = subprocess.run(
            [str(args.avbroot), "--version"], text=True,
            capture_output=True, check=False, timeout=15
        )
        if version.returncode != 0 or "3.34.1" not in (
            version.stdout + version.stderr
        ):
            parser.error("avbroot executable is not version 3.34.1")
        result = subprocess.run(
            [str(args.avbroot), "ota", "verify", "--input", str(args.ota),
             "--public-key-avb", str(args.avb_pkmd),
             "--cert-ota", str(args.ota_cert)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False, timeout=2400
        )
        if result.returncode == 0 or "Care map does not match:" not in result.stdout:
            raise RuntimeError(
                "expected care-map-only avbroot v3.34.1 mismatch not reproduced; "
                f"status={result.returncode}; final output={result.stdout[-3000:]}"
            )
        print("EXPECTED FAIL: avbroot 3.34.1 reports source care-map inequality")
        print("This is NOT proof of source corruption, nor OTA publish authorization.")

    if not publisher_supplied:
        print("Publisher verification NOT rerun here; byte identity matches authenticated issue witness.")
    if not external_supplied:
        print("avbroot 3.34.1 execution NOT rerun here; reference mismatch tests are separate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
