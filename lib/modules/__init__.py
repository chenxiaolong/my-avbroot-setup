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
