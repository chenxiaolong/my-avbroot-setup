# SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from collections.abc import Iterable
import logging
import os
from pathlib import Path
import shutil
import tempfile
from typing import override
import zipfile

from lib import modules
from lib.filesystem import CpioFs, ExtFs
from lib.initscript import InitScript
from lib.linux import linux_android_abi, linux_run
from lib.modules import Module, ModuleRequirements


logger = logging.getLogger(__name__)


class MSDModule(Module):
    def __init__(self, zip: Path, sig: Path) -> None:
        super().__init__()

        modules.verify_ssh_sig(zip, sig, modules.SSH_PUBLIC_KEY_CHENXIAOLONG)

        self.zip: Path = zip
        self.abi: str = linux_android_abi()

    @override
    def requirements(self) -> ModuleRequirements:
        return ModuleRequirements(
            boot_images=set(),
            ext_images={'system'},
            selinux_patching=True,
        )

    @override
    def inject(
        self,
        boot_fs: dict[str, CpioFs],
        ext_fs: dict[str, ExtFs],
        sepolicies: Iterable[Path],
        compatible_sepolicy: bool = False,
    ) -> None:
        logger.info(f'Injecting MSD: {self.zip}')

        system_fs = ext_fs['system']

        with zipfile.ZipFile(self.zip, 'r') as z:
            for path in z.namelist():
                if path == 'msd-tool.arm64-v8a':
                    dest_path = 'system/bin/msd-tool'
                    perms = 0o755
                elif path.endswith('.apk') or path.endswith('.xml'):
                    dest_path = path
                    perms = 0o644
                else:
                    continue

                modules.zip_extract(z, path, system_fs, mode=perms, output=dest_path)

            # Add SELinux rules.
            with tempfile.NamedTemporaryFile(delete_on_close=False) as f_temp:
                with z.open(f'msd-tool.{self.abi}') as f_exe:
                    shutil.copyfileobj(f_exe, f_temp)
                os.fchmod(f_temp.fileno(), 0o700)
                f_temp.close()

                for sepolicy in sepolicies:
                    if compatible_sepolicy and not sepolicy.exists():
                        logger.warning(f'SELinux policy does not exist: {sepolicy}')
                        continue
                    logger.info(f'Adding MSD SELinux rules: {sepolicy}')

                    linux_run(
                        [
                            f_temp.name,
                            'sepatch',
                            '--source', sepolicy,
                            '--target', sepolicy,
                        ],
                        inputs=[f_temp.name, sepolicy],
                        outputs=[sepolicy],
                    )

            # Append seapp_contexts to all relevant partitions
            modules.append_seapp_contexts(z, 'plat_seapp_contexts', ext_fs, compatible_sepolicy)

        InitScript(
            name='msd_daemon',
            command=[
                '/system/bin/msd-tool',
                'daemon',
                '--log-target', 'logcat',
                '--log-level', 'debug',
            ],
            class_='main',
            user='system',
            group='system',
            seclabel='u:r:msd_daemon:s0',
            capabilities=['CHOWN'],
        ).add_to(system_fs)
