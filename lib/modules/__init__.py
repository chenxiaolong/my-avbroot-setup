# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from abc import ABC, abstractmethod
from collections.abc import Iterable
import dataclasses
import logging
from pathlib import Path, PurePosixPath
import platform
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


def host_android_abi() -> str:
    arch = platform.machine()

    if arch == 'x86_64':
        return arch
    elif arch == 'i386' or arch == 'i486' or arch == 'i586' or arch == 'i686':
        return 'x86'
    elif arch == 'aarch64':
        return 'arm64-v8a'
    elif arch.startswith('armv7'):
        return 'armeabi-v7a'
    else:
        raise ValueError(f'Unknown architecture: {arch}')


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
