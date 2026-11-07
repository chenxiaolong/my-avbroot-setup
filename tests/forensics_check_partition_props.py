# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only opt-in recovery of authenticated *original* ext4 build props.

Expected hashes and precise paths come from the publisher-authenticated
October 9 source, ModOS forensic run 38181164127. This DOES NOT download
or publish images, independently verify a publisher signature, or attest
the patched output filesystem or effective runtime Android properties.
Only use original raw partitions independently extracted from trusted OTA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from tests import care_map_reference as reference


_ALLOWED_BUILD_PROP_PATHS = frozenset((
    "/build.prop", "/etc/build.prop", "/system/build.prop",
))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while data := source.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def strict_property_from_build_prop(data: bytes, property_id: str) -> str:
    """Require one exact, printable ro.<partition>.build.fingerprint assignment.

    An unqualified ro.build.fingerprint, alternate partition property, comment,
    substring occurrence or AVB descriptor is never a substitute.
    """
    if not property_id.startswith("ro.") or not property_id.endswith(
        ".build.fingerprint"
    ):
        raise ValueError("unexpected runtime property identifier")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("non-UTF8 build.prop") from exc
    matches = []
    for line in text.splitlines():
        if "\x00" in line:
            raise ValueError("NUL in build.prop")
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key == property_id:
            matches.append(value)
    if len(matches) != 1:
        raise ValueError(
            f"{property_id}: missing/ambiguous/duplicate filesystem property"
        )
    value = matches[0]
    if not 1 <= len(value) <= 512 or not all(
        33 <= ord(c) <= 126 for c in value
    ):
        raise ValueError(f"{property_id}: invalid filesystem fingerprint")
    return value


def inspect_original_images(
    images_dir: Path,
    *,
    debugfs_command: str = "debugfs",
) -> list[dict]:
    """Read-only ext4 lookup; independently pinned image hashes first."""
    original = reference.parse_map(reference.source_bytes())
    witness = reference.witness()
    if len(witness["partitions"]) != 6:
        raise ValueError("incomplete historical partition evidence witness")
    if set(original) != {p["name"] for p in witness["partitions"]}:
        raise ValueError("source map differs from historical partition list")

    evidence = []
    for part in witness["partitions"]:
        name = part["name"]
        build_prop_path = part.get("original_filesystem_build_prop_path")
        if build_prop_path not in _ALLOWED_BUILD_PROP_PATHS:
            raise ValueError(f"{name}: missing/unreviewed original build.prop path")
        path = images_dir / f"{name}.img"
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{name}: missing or symbolic-link raw original image")
        observed_hash = sha256_file(path)
        if observed_hash != part["payload_image_sha256"]:
            raise ValueError(f"{name}: original signed-image SHA-256 mismatch")
        cmd = [debugfs_command, "-R", f"cat {build_prop_path}", str(path)]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, check=False
        )
        if result.returncode != 0:
            raise ValueError(f"{name}: read-only debugfs could not read build.prop")
        property_id = original[name]["id"]
        value = strict_property_from_build_prop(result.stdout, property_id)
        if value != original[name]["fingerprint"]:
            raise ValueError(f"{name}: source filesystem/property care-map mismatch")
        evidence.append({
            "name": name,
            "signed_image_sha256": observed_hash,
            "build_prop_path": build_prop_path,
            "property_id": property_id,
            "fingerprint": value,
        })
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-image-dir", type=Path, required=True)
    parser.add_argument("--debugfs", default="debugfs",
                        help="Read-only debugfs executable, not a trust anchor")
    args = parser.parse_args()
    result = inspect_original_images(
        args.original_image_dir, debugfs_command=args.debugfs
    )
    print(json.dumps({
        "status": "ORIGINAL-FILESYSTEM-PROPERTY-WITNESS-ONLY",
        "partitions": result,
        "no_signed_output_or_runtime_proof": True
    }, indent=2))


if __name__ == "__main__":
    main()
