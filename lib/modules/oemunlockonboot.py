# SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from collections.abc import Iterable
from pathlib import Path
import logging
from typing import override
import zipfile

from lib import modules
from lib.filesystem import CpioFs, ExtFs
from lib.initscript import InitScript
from lib.modules import ModuleRequirements, SignedZipCliModule


logger = logging.getLogger(__name__)


class OEMUnlockOnBootModule(SignedZipCliModule):
    NAME: str = 'oemunlockonboot'

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
        logger.info(f'Injecting OEMUnlockOnBoot: {self.zip}')

        system_fs = ext_fs['system']

        with zipfile.ZipFile(self.zip, 'r') as z:
            apk = next(n for n in z.namelist() if n.endswith('.apk'))
            # Intentionally put it somewhere that won't be picked up by
            # Android's package manager since it's not really an app and the apk
            # is unsigned.
            path = 'system/bin/oemunlockonboot.apk'

            modules.zip_extract(z, apk, system_fs, output=path)

        InitScript(
            name='oemunlockonboot',
            command=[
                '/system/bin/app_process',
                '/',
                'com.chiller3.oemunlockonboot.Main',
            ],
            class_='main',
            user='system',
            group='system',
            seclabel='u:r:su:s0',
            env={
                'CLASSPATH': f'/{path}',
            },
        ).add_to(system_fs)
