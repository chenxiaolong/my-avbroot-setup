#!/usr/bin/env python3
"""Explicit network smoke: install pinned Rust into empty homes and build offline.

This is separate from default unit discovery; it downloads the compiler, not
OTA images, and never loads signing material or runs the helper patch command.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, required=True)
    args = parser.parse_args()
    args.workdir.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('builder', root / 'tools/care-map/build_and_run.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    toolchain = json.loads((root / 'tools/care-map/source-build.json').read_text())['rust_toolchain']
    with tempfile.TemporaryDirectory(prefix='cold-rust-', dir=args.workdir) as directory:
        work = Path(directory)
        cargo_home, rustup_home = work / 'cargo-home', work / 'rustup-home'
        cargo_home.mkdir(); rustup_home.mkdir()
        assert not list(cargo_home.iterdir()) and not list(rustup_home.iterdir())
        environment = builder.compiler_environment(cargo_home, rustup_home, toolchain)
        subprocess.run(['rustup', 'toolchain', 'install', toolchain, '--profile',
            'minimal', '--no-self-update'], env=environment, stdout=sys.stderr, check=True)
        cargo, rustc = builder.pinned_compiler(environment, toolchain)
        assert rustup_home in cargo.parents and rustup_home in rustc.parents
        source = work / 'tiny'
        (source / 'src').mkdir(parents=True)
        (source / 'Cargo.toml').write_text('[package]\nname="cold-source-proof"\nversion="0.1.0"\nedition="2024"\n')
        (source / 'src/main.rs').write_text('fn main() { println!("cold-pinned-toolchain-ok"); }\n')
        subprocess.run([str(cargo), 'generate-lockfile', '--offline'], cwd=source, env=environment, check=True)
        subprocess.run([str(cargo), 'build', '--release', '--locked', '--offline'], cwd=source, env=environment, check=True)
        binary = source / 'target/release/cold-source-proof'
        output = subprocess.check_output([str(binary)], text=True).strip()
        assert output == 'cold-pinned-toolchain-ok'
        print(json.dumps({'schema': 'modos-cold-toolchain-smoke-v1',
            'initial_cargo_home_empty': True, 'initial_rustup_home_empty': True,
            'rustup_install_no_self_update': 'PASS', 'direct_pinned_cargo_build': 'PASS',
            'compiler_inside_task_rustup_home': True,
            'rustc': subprocess.check_output([str(rustc), '-V'], env=environment, text=True).strip(),
            'cargo': subprocess.check_output([str(cargo), '-V'], env=environment, text=True).strip(),
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'compiled_binary_execution': output}, indent=2))


if __name__ == '__main__':
    main()
