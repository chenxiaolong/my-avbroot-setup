# SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import argparse
from collections.abc import Iterable
import logging
from pathlib import Path
from typing import override
import zipfile

from lib import modules
from lib.filesystem import CpioFs, ExtFs
from lib.initscript import InitScript
from lib.modules import Module, ModuleRequirements


logger = logging.getLogger(__name__)


class BCRModule(Module):
    NAME: str = 'bcr'

    @classmethod
    @override
    def add_args(cls, parser: argparse.ArgumentParser):
        modules.add_signed_module_args(parser, cls.NAME)

    def __init__(self, args: argparse.Namespace) -> None:
        self.zip: Path = modules.get_signed_module_args(
            args,
            self.NAME,
            modules.SSH_PUBLIC_KEY_CHENXIAOLONG,
        )

    @override
    def requirements(self) -> ModuleRequirements:
        return ModuleRequirements(
            boot_images=set(),
            ext_images={'system'},
            selinux_patching=False,
        )

    @override
    def inject(
        self,
        boot_fs: dict[str, CpioFs],
        ext_fs: dict[str, ExtFs],
        sepolicies: Iterable[Path],
        compatible_sepolicy: bool = False,
    ) -> None:
        logger.info(f'Injecting BCR: {self.zip}')

        system_fs = ext_fs['system']
        apk = None

        with zipfile.ZipFile(self.zip, 'r') as z:
            for path in z.namelist():
                if not path.endswith('.apk') and not path.endswith('.xml'):
                    continue
                elif path.endswith('.apk'):
                    apk = path

                modules.zip_extract(z, path, system_fs)

        assert apk

        InitScript(
            name='bcr_remove_hard_restrictions',
            command=[
                '/system/bin/app_process',
                '/',
                'com.chiller3.bcr.standalone.RemoveHardRestrictionsKt',
            ],
            class_='main',
            user='system',
            group='system',
            seclabel='u:r:su:s0',
            env={
                'CLASSPATH': f'/{apk}',
            },
        ).add_to(system_fs)
