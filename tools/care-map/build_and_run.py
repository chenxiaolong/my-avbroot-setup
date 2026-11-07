#!/usr/bin/env python3
"""Build the reviewed development source, then authorize only those built bytes.

The fixed checked-in manifest is source authorization. The generated receipt is
review evidence; it is deliberately never loaded as executable authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

DIRECTORY = Path(__file__).resolve().parent
HELPER = DIRECTORY.parents[1]
MANIFEST = DIRECTORY / 'source-build.json'
PATCH = DIRECTORY / 'avbroot-runtime-care-map.patch'
BUILD_ENVIRONMENT = frozenset({
    'PATH', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
})


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_clean(repository: Path, paths: list[Path]) -> None:
    relative = [str(path.relative_to(repository)) for path in paths]
    subprocess.run(['git', '-C', str(repository), 'ls-files', '--error-unmatch',
        '--', *relative], stdout=subprocess.DEVNULL, check=True)
    subprocess.run(['git', '-C', str(repository), 'diff', '--quiet', 'HEAD',
        '--', *relative], check=True)


def load_source() -> tuple[dict[str, str], bytes, str]:
    require_clean(HELPER, [MANIFEST, PATCH, Path(__file__).resolve(),
        DIRECTORY / 'dev_tool_runner.py'])
    revision = subprocess.check_output(['git', '-C', str(HELPER), 'rev-parse', 'HEAD'], text=True).strip()
    def committed(path: Path) -> bytes:
        return subprocess.check_output(['git', '-C', str(HELPER), 'show',
            f'{revision}:{path.relative_to(HELPER)}'])
    manifest = json.loads(committed(MANIFEST))
    patch_bytes = committed(PATCH)
    if manifest.get('schema') != 'avbroot-development-source-v1':
        raise ValueError('unsupported development source manifest')
    if manifest.get('repository') != 'https://github.com/chenxiaolong/avbroot.git':
        raise ValueError('unexpected upstream source repository')
    for key, pattern in [('base_commit', r'[0-9a-f]{40}'),
                         ('patch_sha256', r'[0-9a-f]{64}'),
                         ('cargo_lock_sha256', r'[0-9a-f]{64}'),
                         ('rust_toolchain', r'\d+\.\d+\.\d+')]:
        if not isinstance(manifest.get(key), str) or not re.fullmatch(pattern, manifest[key]):
            raise ValueError(f'invalid source manifest {key}')
    if hashlib.sha256(patch_bytes).hexdigest() != manifest['patch_sha256']:
        raise ValueError('source patch differs from reviewed manifest')
    return manifest, patch_bytes, revision


def compiler_environment(cargo_home: Path, rustup_home: Path, toolchain: str) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
        if key in BUILD_ENVIRONMENT}
    environment.update(CARGO_HOME=str(cargo_home), RUSTUP_HOME=str(rustup_home),
        RUSTUP_TOOLCHAIN=toolchain)
    return environment


def pinned_compiler(environment: dict[str, str], toolchain: str) -> tuple[Path, Path]:
    """Resolve installed toolchain binaries without invoking global rustup proxies."""
    programs = []
    for name in ('cargo', 'rustc'):
        value = subprocess.check_output(['rustup', 'which', '--toolchain',
            toolchain, name], env=environment, text=True).strip()
        program = Path(value)
        if not program.is_absolute() or not program.is_file():
            raise ValueError(f'pinned toolchain {name} is unavailable')
        programs.append(program)
    cargo, rustc = programs
    # This value is derived internally from the installed pinned toolchain;
    # caller RUSTC/RUSTC_WRAPPER values never enter the compiler environment.
    environment['RUSTC'] = str(rustc)
    environment['PATH'] = str(rustc.parent) + os.pathsep + environment.get('PATH', '')
    return cargo, rustc


def build_prefix(args: argparse.Namespace) -> tuple[list[str], dict[str, object]]:
    manifest, patch_bytes, helper_revision = load_source()
    modos = args.modos_repo.resolve()
    require_clean(modos, [modos / 'src' / name for name in (
        'bootstrap_archive.py', 'bootstrap_executable_tools.py', 'bootstrap_io.py',
        'validate_executable_tool_lock.py')])
    work = args.build_workdir.resolve()
    # Never authorize an existing build or a cached receipt.
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    cargo_home = (args.cargo_home or work / 'cargo-home').resolve()
    rustup_home = (args.rustup_home or work / 'rustup-home').resolve()
    cargo_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    rustup_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = compiler_environment(cargo_home, rustup_home, manifest['rust_toolchain'])
    checkout = work / 'source'
    def run(command: list[str], *, cwd: Path | None = None, input_data: bytes | None = None) -> None:
        subprocess.run(command, cwd=cwd, env=environment, stdout=sys.stderr,
            input=input_data, check=True)
    run(['git', 'clone', '--no-checkout', '--', manifest['repository'], str(checkout)])
    run(['git', 'checkout', '--detach', manifest['base_commit']], cwd=checkout)
    run(['git', 'apply', '--index', '-'], cwd=checkout, input_data=patch_bytes)
    if sha256(checkout / 'Cargo.lock') != manifest['cargo_lock_sha256']:
        raise ValueError('patched Cargo.lock differs from reviewed manifest')
    run(['rustup', 'toolchain', 'install', manifest['rust_toolchain'], '--profile', 'minimal', '--no-self-update'])
    cargo_program, rustc_program = pinned_compiler(environment, manifest['rust_toolchain'])
    run([str(cargo_program), 'build', '--release', '--locked', '-p', 'avbroot',
        '--no-default-features'], cwd=checkout)
    if getattr(args, 'validate_source', False):
        run([str(cargo_program), 'test', '--release', '--locked', '-p', 'avbroot',
            '--no-default-features'], cwd=checkout)
    binary = checkout / 'target' / 'release' / 'avbroot'
    digest, size = sha256(binary), binary.stat().st_size
    # Capture identities before discarding the fresh checkout and its large
    # compilation intermediates. Keep only the newly measured executable;
    # the parent still authorizes its bytes, never the generated receipt.
    rustc = subprocess.check_output([str(rustc_program), '-vV'], env=environment, text=True).strip()
    cargo = subprocess.check_output([str(cargo_program), '-V'], env=environment, text=True).strip()
    retained_binary = work / 'avbroot'
    binary.replace(retained_binary)
    shutil.rmtree(checkout)
    # Default homes belong to this fresh build and are unused during OTA
    # processing. Explicit caller homes remain available to their owner.
    explicit_homes = [path.resolve() for path in (args.cargo_home, args.rustup_home)
                      if path is not None]
    for home, supplied in ((cargo_home, args.cargo_home), (rustup_home, args.rustup_home)):
        if supplied is None and not any(home == explicit or home in explicit.parents
                                        for explicit in explicit_homes):
            shutil.rmtree(home)
    prefix = ['/usr/bin/python3', str(DIRECTORY / 'dev_tool_runner.py'),
        '--modos-repo', str(modos), '--bootstrap-workdir', str(args.bootstrap_workdir.resolve()),
        '--built-binary', str(retained_binary), '--built-sha256', digest, '--built-size', str(size)]
    receipt = {'schema': 'avbroot-development-build-v1', 'source': manifest,
        'helper_revision': helper_revision,
        'rustc': rustc, 'cargo': cargo, 'binary_sha256': digest, 'binary_size': size,
        'build_command': ['cargo', 'build', '--release', '--locked', '-p', 'avbroot', '--no-default-features'],
        'source_validation': 'full-tests-passed' if getattr(args, 'validate_source', False) else 'not-run',
        'scope': 'local nonpublishing development build; no vendor executable-lock promotion'}
    (work / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return prefix, receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--modos-repo', type=Path, required=True)
    parser.add_argument('--bootstrap-workdir', type=Path, required=True)
    parser.add_argument('--build-workdir', type=Path, required=True)
    parser.add_argument('--validate-source', action='store_true',
                        help='Run the full upstream and guarded-patch tests before compiler cleanup')
    parser.add_argument('--cargo-home', type=Path)
    parser.add_argument('--rustup-home', type=Path)
    parser.add_argument('--prepare-only', action='store_true',
        help='Print fresh-build argv prefix JSON for the trusted parent to retain in memory')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.arguments and args.arguments[0] == '--':
        args.arguments = args.arguments[1:]
    if any(value.split('=', 1)[0] == '--tool-runner-prefix-json' for value in args.arguments):
        parser.error('the development builder owns the authenticated tool runner prefix')
    if args.prepare_only and args.arguments:
        parser.error('--prepare-only accepts no helper arguments')
    if not args.prepare_only and not args.arguments:
        parser.error('provide helper arguments or --prepare-only')
    try:
        prefix, _receipt = build_prefix(args)
        encoded = json.dumps(prefix, separators=(',', ':'))
        if args.prepare_only:
            print(encoded)
        else:
            subprocess.run([sys.executable, str(HELPER / 'patch.py'),
                *args.arguments, '--tool-runner-prefix-json', encoded], check=True)
    except subprocess.CalledProcessError as error:
        print(f'development source operation failed (exit {error.returncode})', file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f'development source build failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
