# SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from abc import ABC, abstractmethod
import argparse
from collections.abc import Iterable
import dataclasses
import functools
import logging
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import zipfile

from lib.filesystem import CpioFs, ExtFs


logger = logging.getLogger(__name__)


# https://codeberg.org/chenxiaolong/chenxiaolong
# https://gitlab.com/chenxiaolong/chenxiaolong
# https://github.com/chenxiaolong/chenxiaolong
SSH_PUBLIC_KEY_CHENXIAOLONG = \
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOe6/tBnO7xZhAWXRj3ApUYgn+XZ0wnQiXM8B7tPgv4'


class MissingArgs(Exception):
    pass


def verify_ssh_sig(zip: Path, sig: Path, public_key: str):
    logger.info(f'Verifying SSH signature: {zip}')

    with tempfile.NamedTemporaryFile(delete_on_close=False) as f_trusted:
        f_trusted.write(b'trusted ')
        f_trusted.write(public_key.encode('UTF-8'))
        f_trusted.close()

        with open(zip, 'rb') as f_zip:
            subprocess.check_call([
                'ssh-keygen',
                '-Y', 'verify',
                '-f', f_trusted.name,
                '-I', 'trusted',
                '-n', 'file',
                '-s', sig,
            ], stdin=f_zip)


def add_signed_module_args(parser: argparse.ArgumentParser, name: str):
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


def get_signed_module_args(args: argparse.Namespace, name: str, public_key: str) -> Path:
    zip: Path | None = getattr(args, f'module_{name}')
    if zip is None:
        raise MissingArgs()

    sig: Path | None = getattr(args, f'module_{name}_sig')
    if sig is None:
        sig = Path(f'{zip}.sig')

    verify_ssh_sig(zip, sig, public_key)

    return zip


def zip_extract(
    zip: zipfile.ZipFile,
    name: str,
    fs: ExtFs,
    mode: int = 0o644,
    parent_mode: int = 0o755,
    output: str | None = None,
):
    path = PurePosixPath(output or name)

    fs.mkdir(path.parent, mode=parent_mode, parents=True, exist_ok=True)
    with fs.open(path, 'wb', mode=mode) as f_out:
        with zip.open(name, 'r') as f_in:
            shutil.copyfileobj(f_in, f_out)


def append_seapp_contexts(
    zip: zipfile.ZipFile,
    seapp_contexts_name: str,
    ext_fs: dict[str, ExtFs],
    compatible_sepolicy: bool = False,
):
    """
    Append seapp_contexts from a module zip to the appropriate partition files.

    In compatible mode, appends to all partition-specific seapp_contexts files
    (plat, vendor, odm) to ensure consistent app labeling across partitions.

    Args:
        zip: Module zipfile containing seapp_contexts
        seapp_contexts_name: Name of the seapp_contexts file in the zip
        ext_fs: Dictionary of filesystem objects by partition name
        compatible_sepolicy: If True, also append to vendor/odm seapp_contexts
    """
    # Always append to plat_seapp_contexts
    system_fs = ext_fs['system']
    plat_seapp = 'system/etc/selinux/plat_seapp_contexts'
    logger.info(f'Adding seapp contexts to: {plat_seapp}')

    with (
        zip.open(seapp_contexts_name, 'r') as f_in,
        system_fs.open(plat_seapp, 'ab') as f_out,
    ):
        shutil.copyfileobj(f_in, f_out)
        f_out.write(b'\n')

    # In compatible mode, also append to vendor/odm seapp_contexts if they exist
    if compatible_sepolicy:
        for partition_name in ['vendor', 'odm']:
            if partition_name not in ext_fs:
                continue

            partition_fs = ext_fs[partition_name]
            seapp_file = f'{partition_name}/etc/selinux/{partition_name}_seapp_contexts'
            seapp_path = (
                partition_fs.tree
                / partition_name
                / 'etc'
                / 'selinux'
                / f'{partition_name}_seapp_contexts'
            )

            if seapp_path.exists():
                logger.info(f'Adding seapp contexts to: {seapp_file} (compatible mode)')
                with (
                    zip.open(seapp_contexts_name, 'r') as f_in,
                    partition_fs.open(seapp_file, 'ab') as f_out,
                ):
                    shutil.copyfileobj(f_in, f_out)
                    f_out.write(b'\n')
            else:
                logger.info(f'Skipping {seapp_file}: file does not exist')


def patch_vendor_cil_for_ueventd(
    ext_fs: dict[str, ExtFs],
    compatible_sepolicy: bool = False,
):
    """
    Add ueventd firmware access rules to vendor/odm CIL files for persistence.

    This ensures that ueventd can access vendor firmware files (like ipa_fws.mdt)
    even after LineageOS or other ROMs recompile SELinux policies from CIL sources
    during Custota live updates. Without these rules, the device may bootloop due
    to firmware loading failures.

    The rules are added to CIL source files (not just precompiled binaries) so they
    persist through boot-time policy recompilation. Binary policies are still
    patched separately by custota-selinux for immediate use.

    Args:
        ext_fs: Dictionary of filesystem objects by partition name
        compatible_sepolicy: If True, also patch odm_sepolicy.cil
    """
    # CIL rules for ueventd to access vendor firmware files
    # This fixes bootloops caused by firmware loading failures (e.g., ipa_fws.mdt)
    ueventd_firmware_rules = """
; Added by my-avbroot-setup --compatible-sepolicy
; Allow ueventd to access vendor firmware files during boot
; Fixes bootloop from IPA/firmware loading failures during Custota updates
(allow ueventd vendor_firmware_file (file (read open getattr)))
(allow ueventd vendor_firmware_file (dir (read open search)))
"""

    # Patch vendor CIL if it exists
    if 'vendor' in ext_fs:
        vendor_cil_path = (
            ext_fs['vendor'].tree
            / 'vendor'
            / 'etc'
            / 'selinux'
            / 'vendor_sepolicy.cil'
        )

        if vendor_cil_path.exists():
            # Check if rules already exist to avoid duplicates
            existing_content = vendor_cil_path.read_text()
            if 'my-avbroot-setup --compatible-sepolicy' in existing_content:
                logger.info(
                    'Ueventd firmware rules already present in vendor_sepolicy.cil'
                )
            else:
                with open(vendor_cil_path, 'a') as f:
                    f.write(ueventd_firmware_rules)
                logger.info(
                    'Added ueventd firmware access rules to vendor_sepolicy.cil'
                )
        else:
            logger.warning(f'vendor_sepolicy.cil not found at {vendor_cil_path}')

    # Patch ODM CIL if --compatible-sepolicy is enabled and ODM partition exists
    if compatible_sepolicy and 'odm' in ext_fs:
        odm_cil_path = (
            ext_fs['odm'].tree
            / 'odm'
            / 'etc'
            / 'selinux'
            / 'odm_sepolicy.cil'
        )

        if odm_cil_path.exists():
            existing_content = odm_cil_path.read_text()
            if 'my-avbroot-setup --compatible-sepolicy' in existing_content:
                logger.info(
                    'Ueventd firmware rules already present in odm_sepolicy.cil'
                )
            else:
                with open(odm_cil_path, 'a') as f:
                    f.write(ueventd_firmware_rules)
                logger.info('Added ueventd firmware access rules to odm_sepolicy.cil')
        else:
            logger.info(
                f'odm_sepolicy.cil not found at {odm_cil_path} '
                '(may not exist on this ROM)'
            )


def patch_cil_policy(
    cil_path: Path,
    rules: list[str],
    marker: str = '; Added by my-avbroot-setup',
) -> None:
    """Append SELinux rules to a CIL policy file once."""
    if not cil_path.exists():
        logger.warning(f'CIL file does not exist: {cil_path}')
        return

    if marker in cil_path.read_text():
        logger.info(f'CIL file already patched: {cil_path}')
        return

    with open(cil_path, 'a') as f:
        f.write(f'\n{marker}\n')
        for rule in rules:
            f.write(f'{rule}\n')

    logger.info(f'Patched CIL file: {cil_path}')


def get_cil_rules_for_partition(
    ext_fs: dict[str, ExtFs],
    partition: str,
    cil_rules: list[str],
    marker: str = '; Added by my-avbroot-setup',
) -> list[str]:
    """Patch a partition's CIL policy when that partition and file exist."""
    if partition not in ext_fs:
        return []

    cil_path = (
        ext_fs[partition].tree
        / partition
        / 'etc'
        / 'selinux'
        / f'{partition}_sepolicy.cil'
    )

    if not cil_path.exists():
        logger.info(
            f'{partition}_sepolicy.cil not found (may not exist on this ROM)'
        )
        return []

    patch_cil_policy(cil_path, cil_rules, marker)
    return [str(cil_path)]


@dataclasses.dataclass
class ModuleRequirements:
    boot_images: set[str]
    ext_images: set[str]
    selinux_patching: bool


class Module(ABC):
    @classmethod
    @abstractmethod
    def add_args(cls, parser: argparse.ArgumentParser):
        ...

    @abstractmethod
    def __init__(self, args: argparse.Namespace):
        ...

    @abstractmethod
    def requirements(self) -> ModuleRequirements:
        ...

    @abstractmethod
    def inject(
        self,
        boot_fs: dict[str, CpioFs],
        ext_fs: dict[str, ExtFs],
        sepolicies: Iterable[Path],
        compatible_sepolicy: bool = False,
    ) -> None:
        ...


@functools.cache
def all_modules() -> list[type[Module]]:
    from lib.modules.alterinstaller import AlterInstallerModule
    from lib.modules.bcr import BCRModule
    from lib.modules.custota import CustotaModule
    from lib.modules.msd import MSDModule
    from lib.modules.oemunlockonboot import OEMUnlockOnBootModule

    return [
        AlterInstallerModule,
        BCRModule,
        CustotaModule,
        MSDModule,
        OEMUnlockOnBootModule,
    ]
