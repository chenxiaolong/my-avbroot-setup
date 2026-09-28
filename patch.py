#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import argparse
import dataclasses
import logging
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile
import tomlkit

from lib import external, modules
from lib import filesystem
from lib.filesystem import CpioFs, CpioInfo, ExtFs, ExtInfo
from lib.modules.registry import (
    INTERNAL_ADAPTERS,
    LOCKED_ADAPTERS,
    locked_adapter_factories,
)
from lib.modules.catalog import load_catalog
from lib.modules.report import (
    AdapterPatchResult,
    build_patch_report,
    write_patch_report,
)
from lib.modules.verified import (
    VerifiedSelection,
    construct_locked_adapters,
    open_verified_selection,
)


logger = logging.getLogger(__name__)


_LOCKED_ARGUMENT_NAMES = (
    'module_lock',
    'module_profile',
    'module_cache',
    'patch_report',
)


def _locked_arguments(args: argparse.Namespace) -> tuple[object | None, ...]:
    return tuple(getattr(args, name, None) for name in _LOCKED_ARGUMENT_NAMES)


def _locked_arguments_are_complete(args: argparse.Namespace) -> bool:
    values = _locked_arguments(args)
    return not any(value is not None for value in values) or all(
        value is not None for value in values
    )


@dataclasses.dataclass
class BootImagePaths:
    image: Path
    unpacked: Path
    raw_image: Path
    ramdisk: Path
    metadata: Path
    tree: Path

    def __init__(self, images_dir: Path, unpacked_dir: Path, name: str) -> None:
        self.image = images_dir / f'{name}.img'
        self.unpacked = unpacked_dir / name
        self.raw_image = self.unpacked / 'raw.img'
        self.ramdisk = self.unpacked / 'ramdisk.img.0'
        self.metadata = self.unpacked / 'cpio.toml'
        self.tree = self.unpacked / 'cpio_tree'


@dataclasses.dataclass
class ExtImagePaths:
    image: Path
    unpacked: Path
    raw_image: Path
    metadata: Path
    tree: Path

    def __init__(self, images_dir: Path, unpacked_dir: Path, name: str) -> None:
        self.image = images_dir / f'{name}.img'
        self.unpacked = unpacked_dir / name
        self.raw_image = self.unpacked / 'raw.img'
        self.metadata = self.unpacked / 'fs_metadata.toml'
        self.tree = self.unpacked / 'fs_tree'


def get_ota_metadata(ota: Path) -> dict[str, str]:
    props: dict[str, str] = {}

    with zipfile.ZipFile(ota, 'r') as z:
        with z.open('META-INF/com/android/metadata', 'r') as f:
            for line in f:
                line = line.decode('UTF-8').strip()

                key, delim, value = line.partition('=')
                if not delim:
                    raise ValueError(f'Bad OTA metadata line: {line!r}')

                props[key] = value

    return props


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--input',
        type=Path,
        required=True,
        help='Input OTA',
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='Output OTA',
    )
    parser.add_argument(
        '--verify-public-key-avb',
        type=Path,
        help='AVB public key for verifying input OTA',
    )
    parser.add_argument(
        '--verify-cert-ota',
        type=Path,
        help='OTA certificate for verifying input OTA',
    )
    parser.add_argument(
        '--sign-key-avb',
        type=Path,
        required=True,
        help='AVB private key for signing output OTA',
    )
    parser.add_argument(
        '--sign-key-ota',
        type=Path,
        required=True,
        help='OTA private key for signing output OTA',
    )
    parser.add_argument(
        '--sign-cert-ota',
        type=Path,
        required=True,
        help='OTA certificate for signing output OTA',
    )
    parser.add_argument(
        '--debug-shell',
        action='store_true',
        help='Spawn a debug shell before cleaning up temporary directory',
    )
    parser.add_argument(
        '--pass-avb-env-var',
        type=str,
        help='Private key passphrase environment variable for AVB signing',
    )
    parser.add_argument(
        '--pass-ota-env-var',
        type=str,
        help='Private key passphrase environment variable for OTA signing',
    )
    parser.add_argument(
        '--pass-avb-file',
        type=Path,
        help='Private key passphrase file for AVB signing',
    )
    parser.add_argument(
        '--pass-ota-file',
        type=Path,
        help='Private key passphrase file for OTA signing',
    )
    parser.add_argument(
        '--patch-arg',
        action='append',
        help='Extra argument to pass to `avbroot ota patch`',
    )
    parser.add_argument(
        '--secondary-output',
        type=Path,
        help=(
            'Optional second output OTA generated from the same prepared '
            'replacement images'
        ),
    )
    parser.add_argument(
        '--secondary-patch-arg',
        action='append',
        help='Extra argument for the secondary `avbroot ota patch` invocation',
    )
    parser.add_argument(
        '--skip-custota-tool',
        action='store_true',
        help='Skip creating Custota csig file and update JSON file',
    )
    parser.add_argument(
        '--compatible-sepolicy',
        action='store_true',
        help='Change sepolicy files to allow patching other selinux partitions and don\'t fail if selinux is missing.',
    )
    parser.add_argument(
        '--tool-runner-prefix-json',
        dest='_tool_runner_prefix_json',
        metavar='JSON',
        help=(
            'Exact JSON argv prefix for an authenticated external-tool runner; '
            'the default executes legacy bare tool names'
        ),
    )

    for module_type in modules.all_modules():
        module_type.add_args(parser)

    # Keep this separate from the legacy per-module options above.  Locked
    # adapters are selected only by a canonical local profile and lock.
    parser.add_argument(
        '--module-lock',
        type=Path,
        help='Canonical artifact lock for locked native adapters',
    )
    parser.add_argument(
        '--module-profile',
        type=Path,
        help='Local capability and module-selection profile',
    )
    parser.add_argument(
        '--module-cache',
        type=Path,
        help='Content-addressed cache containing all locked artifacts',
    )
    parser.add_argument(
        '--patch-report',
        type=Path,
        help='Atomic deterministic report for locked adapter injection',
    )

    args = parser.parse_args()

    raw_tool_runner_prefix = args._tool_runner_prefix_json
    del args._tool_runner_prefix_json
    try:
        args.tool_runner_prefix = (
            external.parse_tool_runner_prefix_json(raw_tool_runner_prefix)
            if raw_tool_runner_prefix is not None
            else None
        )
    except ValueError:
        parser.error('--tool-runner-prefix-json is invalid')

    if args.output is None:
        args.output = Path(f'{args.input}.patched')

    if args.patch_arg is None:
        args.patch_arg = ['--rootless']

    if args.secondary_patch_arg is None:
        args.secondary_patch_arg = []

    if args.secondary_output is not None:
        if not args.skip_custota_tool:
            parser.error('--secondary-output requires --skip-custota-tool')
        if not args.secondary_patch_arg:
            parser.error(
                '--secondary-output requires at least one --secondary-patch-arg'
            )
        if args.secondary_output == args.output:
            parser.error('--secondary-output must differ from --output')
    elif args.secondary_patch_arg:
        parser.error('--secondary-patch-arg requires --secondary-output')

    if not _locked_arguments_are_complete(args):
        parser.error(
            '--module-lock, --module-profile, --module-cache, and '
            '--patch-report must be supplied together'
        )
    return args


def _patch_output_plans(
    args: argparse.Namespace,
) -> tuple[tuple[Path, list[str]], ...]:
    plans = [(args.output, list(args.patch_arg))]
    secondary_output = getattr(args, 'secondary_output', None)
    if secondary_output is not None:
        secondary_patch_arg = list(getattr(args, 'secondary_patch_arg', ()))
        plans.append((secondary_output, secondary_patch_arg))
    return tuple(plans)


def _patch_ota_outputs(
    args: argparse.Namespace,
    sign_key_avb: external.SigningKey,
    sign_key_ota: external.SigningKey,
    replacements: dict[str, Path],
) -> None:
    for output, patch_args in _patch_output_plans(args):
        external.patch_ota(
            args.input,
            output,
            sign_key_avb,
            sign_key_ota,
            args.sign_cert_ota,
            replacements,
            patch_args,
        )


def _run(
    args: argparse.Namespace,
    temp_dir: Path,
    locked_selection: VerifiedSelection | None,
    locked_adapters: tuple[tuple[str, modules.Module], ...],
):
    sign_key_avb = external.SigningKey(
        args.sign_key_avb,
        args.pass_avb_env_var,
        args.pass_avb_file,
    )
    sign_key_ota = external.SigningKey(
        args.sign_key_ota,
        args.pass_ota_env_var,
        args.pass_ota_file,
    )

    inject_modules: list[tuple[str | None, modules.Module]] = []
    need_boot_fs: set[str] = set()
    need_ext_fs: set[str] = set()
    need_sepolicies = False

    for module_type in modules.all_modules():
        try:
            module = module_type.from_args(args)
        except modules.MissingArgs:
            continue

        inject_modules.append((None, module))

        requirements = module.requirements()
        need_boot_fs |= requirements.boot_images
        need_ext_fs |= requirements.ext_images
        need_sepolicies |= requirements.selinux_patching

    for module_id, module in locked_adapters:
        inject_modules.append((module_id, module))

        requirements = module.requirements()
        need_boot_fs |= requirements.boot_images
        need_ext_fs |= requirements.ext_images
        need_sepolicies |= requirements.selinux_patching

    # If we're messing with any ext filesystems, then we need to load the system
    # images to get the list of SELinux contexts.
    if need_ext_fs:
        need_ext_fs.add('system')

    # If we're patching the SELinux policy, then we need to patch both copies of
    # the precompiled policy.
    if need_sepolicies:
        need_boot_fs.add('vendor_boot')
        need_ext_fs.add('vendor')
        if args.compatible_sepolicy:
            need_ext_fs.add('odm')

    # Verify OTA.
    external.verify_ota(args.input, args.verify_public_key_avb, args.verify_cert_ota)

    # Unpack OTA.
    images_dir = temp_dir / 'images'
    if need_boot_fs or need_ext_fs:
        external.unpack_ota(args.input, images_dir, need_boot_fs | need_ext_fs)

    # Unpack boot images.
    boot_fs: dict[str, CpioFs] = {}
    for name in need_boot_fs:
        paths = BootImagePaths(images_dir, temp_dir, name)

        paths.unpacked.mkdir()
        external.unpack_avb(paths.image, paths.unpacked)
        external.unpack_boot(paths.raw_image, paths.unpacked)
        external.unpack_cpio(paths.ramdisk, paths.unpacked)

        with open(paths.metadata, 'rb') as f:
            info = CpioInfo.model_validate(tomlkit.load(f))

        boot_fs[name] = CpioFs(info=info, tree=paths.tree)

    # Unpack ext filesystem images.
    ext_fs: dict[str, ExtFs] = {}
    for name in need_ext_fs:
        paths = ExtImagePaths(images_dir, temp_dir, name)

        paths.unpacked.mkdir()
        external.unpack_avb(paths.image, paths.unpacked)
        external.unpack_fs(paths.raw_image, paths.unpacked)

        with open(paths.metadata, 'rb') as f:
            info = ExtInfo.model_validate(tomlkit.load(f))

        ext_fs[name] = ExtFs(info=info, tree=paths.tree, contexts=[])

    # Parse SELinux label mappings for use when creating new entries. Prefer
    # partition-specific contexts, which must take precedence over platform
    # contexts, and fall back to platform contexts when no partition mapping is
    # present.
    if ext_fs:
        plat_contexts = filesystem.load_file_contexts(
            ext_fs['system'].tree
            / 'system'
            / 'etc'
            / 'selinux'
            / 'plat_file_contexts'
        )

        for partition_name, fs in ext_fs.items():
            partition_contexts_file = (
                fs.tree
                / partition_name
                / 'etc'
                / 'selinux'
                / f'{partition_name}_file_contexts'
            )

            if partition_contexts_file.exists():
                partition_contexts = filesystem.load_file_contexts(
                    partition_contexts_file
                )
                fs.contexts = partition_contexts + plat_contexts
            else:
                fs.contexts = plat_contexts

    # We only update the precompiled policies and leave the CIL policies alone.
    # Since we're starting from a (hopefully) properly built Android build, we
    # should never run into a situation where the precompiled sepolicy is out of
    # date and needs to be recompiled from the CIL files during boot.
    if need_sepolicies:
        selinux_policies = []

        vendor_boot_sepolicy = boot_fs['vendor_boot'].tree / 'sepolicy'
        if vendor_boot_sepolicy.exists():
            selinux_policies.append(vendor_boot_sepolicy)

        vendor_sepolicy = (
            ext_fs['vendor'].tree / 'etc' / 'selinux' / 'precompiled_sepolicy'
        )
        if vendor_sepolicy.exists():
            selinux_policies.append(vendor_sepolicy)

        if args.compatible_sepolicy and 'odm' in ext_fs:
            odm_sepolicy = (
                ext_fs['odm'].tree / 'etc' / 'selinux' / 'precompiled_sepolicy'
            )
            if odm_sepolicy.exists():
                selinux_policies.append(odm_sepolicy)
    else:
        selinux_policies = []

    # Inject modules.
    locked_results: list[tuple[str, AdapterPatchResult]] = []
    for module_id, module in inject_modules:
        result = module.inject(
            boot_fs,
            ext_fs,
            selinux_policies,
            compatible_sepolicy=args.compatible_sepolicy,
        )
        if module_id is not None:
            if not isinstance(result, AdapterPatchResult):
                raise RuntimeError(
                    f'Locked adapter did not return a patch result: {module_id}'
                )
            locked_results.append((module_id, result))

    # Validate the complete report (including cross-adapter output collisions)
    # before repacking images or creating the output OTA.  The finished report
    # is written only after all output work succeeds.
    locked_report = (
        build_patch_report(locked_selection, tuple(locked_results))
        if locked_selection is not None
        else None
    )

    # Repack ext filesystem images.
    for name, fs in ext_fs.items():
        paths = ExtImagePaths(images_dir, temp_dir, name)

        with open(paths.metadata, 'w') as f:
            tomlkit.dump(fs.info.model_dump(exclude_none=True), f)

        external.pack_fs(paths.raw_image, paths.unpacked)
        external.pack_avb(paths.image, paths.unpacked, sign_key_avb, True)

    # Repack boot images.
    for name, fs in boot_fs.items():
        paths = BootImagePaths(images_dir, temp_dir, name)

        with open(paths.metadata, 'w') as f:
            tomlkit.dump(fs.info.model_dump(exclude_none=True), f)

        external.pack_cpio(paths.ramdisk, paths.unpacked)
        external.pack_boot(paths.raw_image, paths.unpacked)
        external.pack_avb(paths.image, paths.unpacked, sign_key_avb, False)

    # Patch one or two OTA outputs from the same prepared replacement images.
    # The secondary output path intentionally reuses all expensive verification,
    # extraction, module injection, filesystem repacking, and AVB repacking work.
    replacements = {
        name: images_dir / f'{name}.img'
        for name in boot_fs | ext_fs
    }
    _patch_ota_outputs(
        args,
        sign_key_avb,
        sign_key_ota,
        replacements,
    )

    if not args.skip_custota_tool:
        # Generate Custota csig.
        external.generate_csig(args.output, sign_key_ota, args.sign_cert_ota)

        # Generate Custota update-info.
        codename = get_ota_metadata(args.output)['pre-device']
        update_info = args.output.parent / f'{codename}.json'
        external.generate_update_info(update_info, args.output.name)

    if locked_report is not None:
        write_patch_report(
            args.patch_report,
            locked_report,
        )


def run(args: argparse.Namespace, temp_dir: Path):
    """Prepare every locked adapter before any OTA verification or mutation."""

    external.configure_tool_runner(
        getattr(args, 'tool_runner_prefix', None),
        signing_environment_names=(
            getattr(args, 'pass_avb_env_var', None),
            getattr(args, 'pass_ota_env_var', None),
        ),
    )

    if not _locked_arguments_are_complete(args):
        raise ValueError(
            'locked module arguments must be supplied as one complete set'
        )

    if getattr(args, 'module_lock', None) is None:
        return _run(args, temp_dir, None, ())

    catalog = load_catalog(registrations=INTERNAL_ADAPTERS + LOCKED_ADAPTERS)
    selection = open_verified_selection(
        catalog,
        args.module_lock,
        args.module_profile,
        args.module_cache,
    )
    with selection:
        adapters = construct_locked_adapters(
            selection,
            locked_adapter_factories(),
        )
        return _run(args, temp_dir, selection, adapters)


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG,
        format='\x1b[1m[%(levelname)s] %(message)s\x1b[0m',
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code = 0

        try:
            run(args, Path(temp_dir))
        except Exception as e:
            logging.error('Failed to patch OTA', exc_info=e)
            exit_code = 1

        if args.debug_shell:
            shell = os.getenv('SHELL', 'bash')
            logger.info(f'Debug shell: {shell}')
            subprocess.run([shell], cwd=temp_dir)

        exit(exit_code)


if __name__ == '__main__':
    main()
