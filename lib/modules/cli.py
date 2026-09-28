# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""CLI for catalog, lock, artifact, and compatibility stages."""

import argparse
import json
from pathlib import Path

from lib.modules.archive import ArchiveError, ArchiveLimits, inspect_zip
from lib.modules.catalog import CatalogError, load_catalog
from lib.modules.locks import (
    LockError,
    fetch_locked_artifacts,
    load_canonical_lock,
    verify_locked_artifacts,
)
from lib.modules.providers import get_lock_update_provider
from lib.modules.resolver import ResolutionError, load_profile, resolve_profile
from lib.modules.registry import MODULE_ID_PATTERN


def _positive_int(value: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError('must be a positive integer') from error
    if result <= 0:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return result


def _module_id(value: str) -> str:
    if not MODULE_ID_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError('must be a canonical module ID')
    return value


def _add_lock_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--lock',
        type=Path,
        required=True,
        help='Checked-in canonical artifact lock',
    )


def _add_selection_arguments(parser: argparse.ArgumentParser) -> None:
    _add_lock_argument(parser)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument(
        '--module',
        action='append',
        dest='modules',
        type=_module_id,
        help='Limit the operation to a locked module ID (repeatable)',
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='module-tool',
        description='Deterministic patch-module preparation tools',
    )
    commands = parser.add_subparsers(dest='command', required=True)

    catalog = commands.add_parser('catalog', help='Read the local module catalog')
    catalog_commands = catalog.add_subparsers(dest='catalog_command', required=True)
    catalog_list = catalog_commands.add_parser('list')
    catalog_list.add_argument('--format', choices=('text', 'json'), default='text')

    lock = commands.add_parser('lock', help='Update or verify artifact locks')
    lock_commands = lock.add_subparsers(dest='lock_command', required=True)
    lock_verify = lock_commands.add_parser('verify')
    _add_lock_argument(lock_verify)
    lock_update = lock_commands.add_parser('update')
    lock_update.add_argument('module', type=_module_id)
    lock_update.add_argument('--output', type=Path)
    lock_update.add_argument('--version-code', type=_positive_int, action='append')
    lock_update.add_argument('--client-version-code', type=_positive_int)
    lock_update.add_argument('--fpe-ota-version-code', type=_positive_int)

    artifacts = commands.add_parser(
        'artifacts',
        help='Fetch, verify, or safely inspect locked artifacts',
    )
    artifact_commands = artifacts.add_subparsers(
        dest='artifact_command',
        required=True,
    )
    fetch = artifact_commands.add_parser('fetch')
    _add_selection_arguments(fetch)
    verify = artifact_commands.add_parser('verify')
    _add_selection_arguments(verify)
    inspect = artifact_commands.add_parser('inspect')
    inspect.add_argument('archive', type=Path)
    inspect.add_argument('--allow', action='append', required=True)
    inspect.add_argument('--max-members', type=_positive_int, default=4096)
    inspect.add_argument(
        '--max-member-size', type=_positive_int, default=128 * 1024 * 1024
    )
    inspect.add_argument(
        '--max-total-size', type=_positive_int, default=512 * 1024 * 1024
    )
    inspect.add_argument('--max-expansion-ratio', type=_positive_int, default=200)
    inspect.add_argument(
        '--max-streamed-bytes', type=_positive_int, default=512 * 1024 * 1024
    )

    resolve = commands.add_parser(
        'resolve',
        help='Resolve a local module profile against the catalog',
    )
    resolve.add_argument('--profile', type=Path, required=True)
    _add_lock_argument(resolve)
    resolve.add_argument('--format', choices=('text', 'json'), default='text')
    return parser


def _update_lock(args: argparse.Namespace) -> None:
    # Floating metadata is reachable only through this explicit command and a
    # statically reviewed provider.  A module ID is never an import path.
    provider = get_lock_update_provider(args.module)
    if provider is None:
        raise LockError(
            f'no reviewed lock-update provider is available for module: {args.module}'
        )
    if args.module == 'fdroid-privileged-extension':
        if args.version_code:
            raise LockError(
                'F-Droid requires named --client-version-code and '
                '--fpe-ota-version-code selectors'
            )
        if args.output is None:
            raise LockError('F-Droid lock update requires an explicit --output path')
        if args.client_version_code is None or args.fpe_ota_version_code is None:
            raise LockError(
                'F-Droid lock update requires both explicit versionCode selectors'
            )
        lock = provider(
            output=args.output,
            client_version_code=args.client_version_code,
            fpe_ota_version_code=args.fpe_ota_version_code,
        )
        print(lock.as_json(), end='')
        return
    raise AssertionError('reviewed provider has no CLI argument binding')


def _dispatch(args: argparse.Namespace) -> None:
    if args.command == 'catalog':
        catalog = load_catalog()
        output = catalog.as_json() if args.format == 'json' else catalog.as_text()
        print(output, end='')
    elif args.command == 'lock' and args.lock_command == 'verify':
        lock, _ = load_canonical_lock(args.lock)
        print(lock.as_json(), end='')
    elif args.command == 'lock' and args.lock_command == 'update':
        _update_lock(args)
    elif args.command == 'artifacts' and args.artifact_command == 'fetch':
        lock, _ = load_canonical_lock(args.lock)
        paths = fetch_locked_artifacts(
            lock,
            args.cache,
            module_ids=args.modules,
        )
        print(json.dumps([str(path) for path in paths], indent=2) + '\n', end='')
    elif args.command == 'artifacts' and args.artifact_command == 'verify':
        lock, _ = load_canonical_lock(args.lock)
        paths = verify_locked_artifacts(
            lock,
            args.cache,
            module_ids=args.modules,
            verify_apks=True,
        )
        print(json.dumps([str(path) for path in paths], indent=2) + '\n', end='')
    elif args.command == 'artifacts' and args.artifact_command == 'inspect':
        result = inspect_zip(
            args.archive,
            allowlisted_members=args.allow,
            limits=ArchiveLimits(
                max_members=args.max_members,
                max_member_size=args.max_member_size,
                max_total_size=args.max_total_size,
                max_expansion_ratio=args.max_expansion_ratio,
                max_streamed_bytes=args.max_streamed_bytes,
            ),
        )
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True) + '\n', end='')
    elif args.command == 'resolve':
        lock, lock_sha256 = load_canonical_lock(args.lock)
        resolution = resolve_profile(
            load_catalog(),
            load_profile(args.profile),
            lock,
            lock_sha256,
        )
        output = resolution.as_json() if args.format == 'json' else resolution.as_text()
        print(output, end='')
    else:
        raise AssertionError('unhandled command')


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _dispatch(args)
    except (ArchiveError, CatalogError, LockError, ResolutionError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
