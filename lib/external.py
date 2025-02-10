# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from collections.abc import Iterable
import dataclasses
import logging
from pathlib import Path
import subprocess


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class SigningKey:
    key: Path
    pass_env: Path | None
    pass_file: Path | None


def verify_ota(ota: Path, public_key_avb: Path, cert_ota: Path):
    logger.info(f'Verifying OTA: {ota}')

    subprocess.check_call([
        'avbroot', 'ota', 'verify',
        '--input', ota,
        '--public-key-avb', public_key_avb,
        '--cert-ota', cert_ota,
    ])


def unpack_ota(ota: Path, output_dir: Path, partitions: Iterable[str]):
    logger.info(f'Unpacking OTA: {ota}')

    cmd = [
        'avbroot', 'ota', 'extract',
        '--input', ota,
        '--directory', output_dir,
    ]

    for partition in partitions:
        cmd.append('--partition')
        cmd.append(partition)

    subprocess.check_call(cmd)


def patch_ota(
    input_ota: Path,
    output_ota: Path,
    key_avb: SigningKey,
    key_ota: SigningKey,
    cert_ota: Path,
    replace: dict[str, Path],
):
    image_names = ', '.join(sorted(replace.keys()))
    logger.info(f'Patching OTA with replaced images: {image_names}: {output_ota}')

    cmd = [
        'avbroot', 'ota', 'patch',
        '--input', input_ota,
        '--output', output_ota,
        '--key-avb', key_avb.key,
        '--key-ota', key_ota.key,
        '--cert-ota', cert_ota,
        '--rootless',
    ]

    if key_avb.pass_env is not None:
        cmd.append('--pass-avb-env-var')
        cmd.append(key_avb.pass_env)
    elif key_avb.pass_file is not None:
        cmd.append('--pass-avb-file')
        cmd.append(key_avb.pass_file)

    if key_ota.pass_env is not None:
        cmd.append('--pass-ota-env-var')
        cmd.append(key_ota.pass_env)
    elif key_ota.pass_file is not None:
        cmd.append('--pass-ota-file')
        cmd.append(key_ota.pass_file)

    for k, v in replace.items():
        cmd.append('--replace')
        cmd.append(k)
        cmd.append(v)

    subprocess.check_call(cmd)


def unpack_avb(image: Path, output_dir: Path):
    logger.info(f'Unpacking AVB image: {image}')

    subprocess.check_call([
        'avbroot', 'avb', 'unpack',
        '--quiet',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_avb(
    image: Path,
    input_dir: Path,
    key: SigningKey,
    recompute_size: bool,
):
    logger.info(f'Packing AVB image: {image}')

    cmd = [
        'avbroot', 'avb', 'pack',
        '--quiet',
        '--output', image.absolute(),
        '--key', key.key,
    ]

    if key.pass_env is not None:
        cmd.append('--pass-env-var')
        cmd.append(key.pass_env)
    elif key.pass_file is not None:
        cmd.append('--pass-file')
        cmd.append(key.pass_file)

    if recompute_size:
        cmd.append('--recompute-size')

    subprocess.check_call(cmd, cwd=input_dir)


def unpack_boot(image: Path, output_dir: Path):
    logger.info(f'Unpacking boot image: {image}')

    subprocess.check_call([
        'avbroot', 'boot', 'unpack',
        '--quiet',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_boot(image: Path, input_dir: Path):
    logger.info(f'Packing boot image: {image}')

    subprocess.check_call([
        'avbroot', 'boot', 'pack',
        '--quiet',
        '--output', image.absolute(),
    ], cwd=input_dir)


def unpack_cpio(archive: Path, output_dir: Path):
    logger.info(f'Unpacking CPIO archive: {archive}')

    subprocess.check_call([
        'avbroot', 'cpio', 'unpack',
        '--quiet',
        '--input', archive.absolute(),
    ], cwd=output_dir)


def pack_cpio(archive: Path, input_dir: Path):
    logger.info(f'Packing CPIO archive: {archive}')

    subprocess.check_call([
        'avbroot', 'cpio', 'pack',
        '--quiet',
        '--output', archive.absolute(),
    ], cwd=input_dir)


def unpack_fs(image: Path, output_dir: Path):
    logger.info(f'Unpacking filesystem: {image}')

    subprocess.check_call([
        'afsr', 'unpack',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_fs(image: Path, input_dir: Path):
    logger.info(f'Packing filesystem: {image}')

    subprocess.check_call([
        'afsr', 'pack',
        '--output', image.absolute(),
    ], cwd=input_dir)


def generate_csig(ota: Path, key_ota: SigningKey, cert_ota: Path):
    logger.info(f'Generating Custota csig: {ota}.csig')

    cmd = [
        'custota-tool', 'gen-csig',
        '--input', ota,
        '--key', key_ota.key,
        '--cert', cert_ota,
    ]

    if key_ota.pass_env is not None:
        cmd.append('--passphrase-env-var')
        cmd.append(key_ota.pass_env)
    elif key_ota.pass_file is not None:
        cmd.append('--passphrase-file')
        cmd.append(key_ota.pass_file)

    subprocess.check_call(cmd)


def generate_update_info(update_info: Path, location: str):
    logger.info(f'Generating Custota update info: {update_info}')

    subprocess.check_call([
        'custota-tool', 'gen-update-info',
        '--file', update_info,
        '--location', location,
    ])
