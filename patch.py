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


logger = logging.getLogger(__name__)


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
        '--skip-custota-tool',
        action='store_true',
        help='Skip creating Custota csig file and update JSON file',
    )
    parser.add_argument(
        '--compatible-sepolicy',
        action='store_true',
        help='Change sepolicy files to allow patching other selinux partitions and don\'t fail if selinux is missing.',
    )

    for name in modules.all_modules():
        parser.add_argument(
            f'--module-{name}',
            type=Path,
            help=f'{name} module zip',
        )
        parser.add_argument(
            f'--module-{name}-sig',
            type=Path,
            help=f'{name} module zip signature',
        )

    args = parser.parse_args()

    global compatible_sepolicy
    compatible_sepolicy=args.compatible_sepolicy

    if args.output is None:
        args.output = Path(f'{args.input}.patched')

    if args.patch_arg is None:
        args.patch_arg = ['--rootless']

    for name in modules.all_modules():
        sig_key = f'module_{name}_sig'

        if getattr(args, sig_key) is None:
            zip_path: Path = getattr(args, f'module_{name}')
            setattr(args, sig_key, Path(f'{zip_path}.sig'))

    return args


def run(args: argparse.Namespace, temp_dir: Path):
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

    inject_modules: list[modules.Module] = []
    need_boot_fs: set[str] = set()
    need_ext_fs: set[str] = set()
    need_sepolicies = False

    for name, constructor in modules.all_modules().items():
        zip_path: Path | None = getattr(args, f'module_{name}')
        sig_path: Path | None = getattr(args, f'module_{name}_sig')

        if zip_path is None or sig_path is None:
            continue

        module = constructor(zip_path, sig_path)
        inject_modules.append(module)

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
        if args.compatible_sepolicy: need_ext_fs.add('odm')

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

    # Parse SELinux label mappings for use when creating new entries.
    if ext_fs:
        contexts = filesystem.load_file_contexts(ext_fs['system'].tree /
            'system' / 'etc' / 'selinux' / 'plat_file_contexts')

        for _, fs in ext_fs.items():
            fs.contexts = contexts

    # We only update the precompiled policies and leave the CIL policies alone.
    # Since we're starting from a (hopefully) properly built Android build, we
    # should never run into a situation where the precompiled sepolicy is out of
    # date and needs to be recompiled from the CIL files during boot.
    if need_sepolicies:
        selinux_policies = [
            boot_fs['vendor_boot'].tree / 'sepolicy',
            ext_fs['vendor'].tree / 'etc' / 'selinux' / 'precompiled_sepolicy',
        ]
        if args.compatible_sepolicy: selinux_policies.append(ext_fs['odm'].tree / 'etc' / 'selinux' / 'precompiled_sepolicy')
    else:
        selinux_policies = []

    # Inject modules.
    for module in inject_modules:
        module.inject(boot_fs, ext_fs, selinux_policies)

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

    # Patch OTA.
    external.patch_ota(
        args.input,
        args.output,
        sign_key_avb,
        sign_key_ota,
        args.sign_cert_ota,
        {name: images_dir / f'{name}.img' for name in boot_fs | ext_fs},
        args.patch_arg,
    )

    if not args.skip_custota_tool:
        # Generate Custota csig.
        external.generate_csig(args.output, sign_key_ota, args.sign_cert_ota)

        # Generate Custota update-info.
        codename = get_ota_metadata(args.output)['pre-device']
        update_info = args.output.parent / f'{codename}.json'
        external.generate_update_info(update_info, args.output.name)


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
