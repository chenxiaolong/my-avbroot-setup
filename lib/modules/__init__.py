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
from typing import TYPE_CHECKING
import zipfile

from lib.filesystem import CpioFs, ExtFs

if TYPE_CHECKING:
    from lib.modules.report import AdapterPatchResult


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
    from lib.modules.cil_rules import get_cil_rules

    rules = get_cil_rules('ueventd')
    marker = '; Added by my-avbroot-setup --compatible-sepolicy'
    patch_partition_cil_policy(ext_fs, 'vendor', rules, marker)

    if compatible_sepolicy:
        patch_partition_cil_policy(ext_fs, 'odm', rules, marker)


def patch_cil_policy(
    cil_path: Path,
    rules: list[str],
    marker: str = '; Added by my-avbroot-setup',
) -> None:
    """Append SELinux rules to a CIL policy file once."""
    if not cil_path.exists():
        logger.warning(f'CIL file does not exist: {cil_path}')
        return

    if marker in cil_path.read_text().splitlines():
        logger.info(f'CIL file already patched: {cil_path}')
        return

    with open(cil_path, 'a') as f:
        f.write(f'\n{marker}\n')
        for rule in rules:
            f.write(f'{rule}\n')

    logger.info(f'Patched CIL file: {cil_path}')


def patch_partition_cil_policy(
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


def patch_vendor_odm_cil_fallback(
    ext_fs: dict[str, ExtFs],
    module_name: str,
) -> None:
    """Patch direct CIL fallback rules for a module on vendor and ODM."""
    from lib.modules.cil_rules import get_cil_rules

    logger.info('No precompiled sepolicy found, patching CIL files directly')
    rules = get_cil_rules(module_name)
    marker = f'; Added by my-avbroot-setup: {module_name}'
    for partition in ['vendor', 'odm']:
        patch_partition_cil_policy(ext_fs, partition, rules, marker)


@dataclasses.dataclass
class ModuleRequirements:
    boot_images: set[str]
    ext_images: set[str]
    selinux_patching: bool


class Module(ABC):
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
    ) -> 'AdapterPatchResult | None':
        ...


class LegacyCliModule(Module):
    """A reviewed built-in module that owns its legacy CLI contract."""

    @classmethod
    @abstractmethod
    def add_args(cls, parser: argparse.ArgumentParser):
        ...

    @classmethod
    @abstractmethod
    def from_args(cls, args: argparse.Namespace) -> 'LegacyCliModule':
        ...


class SignedZipCliModule(LegacyCliModule):
    """Legacy module with a signed ZIP argument and a fixed trust root."""

    PUBLIC_KEY = SSH_PUBLIC_KEY_CHENXIAOLONG

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser):
        add_signed_module_args(parser, cls.NAME)

    def __init__(self, args: argparse.Namespace) -> None:
        self.zip: Path = get_signed_module_args(args, self.NAME, self.PUBLIC_KEY)

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> 'SignedZipCliModule':
        return cls(args)


@functools.cache
def all_modules() -> list[type[LegacyCliModule]]:
    from lib.modules.registry import legacy_cli_module_types

    # Legacy parsing depends only on this statically reviewed registry. Locked
    # manifests are validated later, and only when locked selection is used.
    return list(legacy_cli_module_types())
