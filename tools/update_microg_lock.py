#!/usr/bin/env python3
"""Prepare a reviewed microG lock only after verifying official APK identities."""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.modules.locks import ArtifactLockFile, fetch_locked_artifacts, verify_locked_artifacts, write_lock
from lib.modules.registry import MICROG_APK_SIGNER_SHA256


def release_lock(release, metadata):
    if not re.fullmatch(r'v[0-9]+(?:\.[0-9]+)+', release):
        raise ValueError('Expected an explicit numeric microG release tag')
    if metadata['tag_name'] != release or metadata['draft'] or metadata['prerelease']:
        raise ValueError('Release is not the requested stable published tag')
    artifacts = []
    for artifact_id, package in [('companion-apk', 'com.android.vending'),
                                 ('gmscore-apk', 'com.google.android.gms')]:
        pattern = re.compile(re.escape(package) + r'-([0-9]+)\.apk')
        candidates = [(asset, pattern.fullmatch(asset['name'])) for asset in metadata['assets']]
        candidates = [(asset, match) for asset, match in candidates if match]
        if len(candidates) != 1:
            raise ValueError(f'Expected exactly one standard custom-ROM APK for {package}')
        asset, match = candidates[0]
        url = f'https://github.com/microg/GmsCore/releases/download/{release}/{asset["name"]}'
        digest = asset.get('digest', '')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest or '') or asset['browser_download_url'] != url:
            raise ValueError('Release asset lacks a SHA-256 or canonical immutable URL')
        artifacts.append({'id': artifact_id, 'kind': 'apk', 'version': match[1],
                          'immutable_url': url, 'sha256': digest[7:], 'size': asset['size'],
                          'allowed_origins': ['https://github.com', 'https://release-assets.githubusercontent.com'],
                          'apk': {'package_name': package, 'version_code': int(match[1]),
                                  'signer_sha256': MICROG_APK_SIGNER_SHA256},
                          'archive': None, 'source_verification': None})
    return ArtifactLockFile.model_validate({'schema_version': 1, 'modules': [
        {'id': 'microg', 'version': release, 'artifacts': artifacts}]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'v[0-9]+(?:\.[0-9]+)+', args.release):
        parser.error('Expected an explicit numeric release tag')
    request = Request(f'https://api.github.com/repos/microg/GmsCore/releases/tags/{args.release}',
                      headers={'User-Agent': 'my-avbroot-setup-microg-lock/1'})
    with urlopen(request, timeout=60) as response:
        metadata = json.load(response)
    lock = release_lock(args.release, metadata)
    fetch_locked_artifacts(lock, args.cache)
    verify_locked_artifacts(lock, args.cache)
    write_lock(args.output, lock)
    print(f'Verified lock written to {args.output}; review adapter constants and permission policy before merging.')


if __name__ == '__main__':
    main()
