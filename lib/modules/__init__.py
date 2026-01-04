# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from abc import ABC, abstractmethod
from collections.abc import Iterable
import dataclasses
import logging
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
from typing import Callable
import zipfile

from lib.filesystem import CpioFs, ExtFs

logger = logging.getLogger(__name__)


# https://codeberg.org/chenxiaolong/chenxiaolong
# https://gitlab.com/chenxiaolong/chenxiaolong
# https://github.com/chenxiaolong/chenxiaolong
SSH_PUBLIC_KEY_CHENXIAOLONG = \
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOe6/tBnO7xZhAWXRj3ApUYgn+XZ0wnQiXM8B7tPgv4'


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
            seapp_path = partition_fs.tree / partition_name / 'etc' / 'selinux' / f'{partition_name}_seapp_contexts'
            
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
    ) -> None:
        ...


def all_modules() -> dict[str, Callable[[Path, Path], Module]]:
    from lib.modules.alterinstaller import AlterInstallerModule
    from lib.modules.bcr import BCRModule
    from lib.modules.custota import CustotaModule
    from lib.modules.msd import MSDModule
    from lib.modules.oemunlockonboot import OEMUnlockOnBootModule

    return {
        'alterinstaller': AlterInstallerModule,
        'bcr': BCRModule,
        'custota': CustotaModule,
        'msd': MSDModule,
        'oemunlockonboot': OEMUnlockOnBootModule,
    }
