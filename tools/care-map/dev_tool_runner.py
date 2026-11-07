#!/usr/bin/env python3
"""Internal ToolRunner transport for one freshly authorized development build.

Digest/size arguments come from build_and_run's live parent process, never from
an environment variable, cached receipt, or user-selected trust manifest.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys


def execute(args: argparse.Namespace) -> None:
    source = args.modos_repo.resolve() / 'src'
    sys.path.insert(0, str(source))
    from bootstrap_archive import open_regular, open_sealed_executable
    from bootstrap_executable_tools import sanitized_environment

    environment = sanitized_environment(os.environ)
    if args.tool != 'avbroot':
        os.execve(sys.executable, [sys.executable,
            str(source / 'bootstrap_executable_tools.py'),
            '--workdir', str(args.bootstrap_workdir.resolve()),
            'run', args.tool, '--', *args.arguments], environment)
        raise RuntimeError('authenticated bootstrap execution unexpectedly returned')
    if not re.fullmatch(r'[0-9a-f]{64}', args.built_sha256) or args.built_size <= 0:
        raise ValueError('invalid parent-derived build identity')
    entry = {'sha256': args.built_sha256, 'size': args.built_size, 'mode': '0500'}
    with open_regular(args.built_binary, args.built_size, 'source-built avbroot') as stream:
        with open_sealed_executable(stream.fileno(), entry) as descriptor:
            os.execve(descriptor, ['avbroot', *args.arguments], environment)
    raise RuntimeError('sealed executable execution unexpectedly returned')


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--modos-repo', type=Path, required=True)
    parser.add_argument('--bootstrap-workdir', type=Path, required=True)
    parser.add_argument('--built-binary', type=Path, required=True)
    parser.add_argument('--built-sha256', required=True)
    parser.add_argument('--built-size', type=int, required=True)
    parser.add_argument('tool', choices=('avbroot', 'afsr', 'custota-tool'))
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    # argparse consumes the transport separator. Later '--' is tool data.
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        execute(parse_args(sys.argv[1:] if argv is None else argv))
    except Exception as error:
        print(f'development tool execution failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
