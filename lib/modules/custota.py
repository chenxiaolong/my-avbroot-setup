# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from collections.abc import Iterable
import logging
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import override
import zipfile

from lib import modules
from lib.filesystem import CpioFs, ExtFs
from lib.modules import Module, ModuleRequirements
from lib.modules.cil_rules import get_cil_rules


logger = logging.getLogger(__name__)


class CustotaModule(Module):
    def __init__(self, zip: Path, sig: Path) -> None:
        super().__init__()

        modules.verify_ssh_sig(zip, sig, modules.SSH_PUBLIC_KEY_CHENXIAOLONG)

        self.zip: Path = zip
        self.abi: str = modules.host_android_abi()

    @override
    def requirements(self) -> ModuleRequirements:
        return ModuleRequirements(
            boot_images=set(),
            ext_images={"system"},
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
        logger.info(f"Injecting Custota: {self.zip}")

        system_fs = ext_fs["system"]

        with zipfile.ZipFile(self.zip, "r") as z:
            for path in z.namelist():
                if not path.endswith(".apk") and not path.endswith(".xml"):
                    continue

                modules.zip_extract(z, path, system_fs)

            # Add SELinux rules.
            with tempfile.NamedTemporaryFile(delete_on_close=False) as f_temp:
                with z.open(f"custota-selinux.{self.abi}") as f_exe:
                    shutil.copyfileobj(f_exe, f_temp)
                os.fchmod(f_temp.fileno(), 0o700)
                f_temp.close()

                for sepolicy in sepolicies:
                    if compatible_sepolicy and not sepolicy.exists():
                        logger.warning(f"SELinux policy does not exist: {sepolicy}")
                        continue

                    logger.info(f"Adding Custota SELinux rules: {sepolicy}")

                    subprocess.check_call(
                        [
                            f_temp.name,
                            "--source",
                            sepolicy,
                            "--target",
                            sepolicy,
                        ]
                    )

            # Append seapp_contexts to all relevant partitions
            modules.append_seapp_contexts(
                z, "plat_seapp_contexts", ext_fs, compatible_sepolicy
            )

        # For LineageOS and other ROMs without precompiled policies, patch CIL files directly
        if compatible_sepolicy and not sepolicies:
            logger.info("No precompiled sepolicy found, patching CIL files directly")
            cil_rules = get_cil_rules("custota")

            # Patch vendor and ODM CIL files
            for partition in ["vendor", "odm"]:
                modules.get_cil_rules_for_partition(ext_fs, partition, cil_rules)

        # Patch vendor/odm CIL files with ueventd firmware rules for persistence
        # This fixes bootloops caused by LineageOS recompiling policies during Custota updates
        if compatible_sepolicy:
            modules.patch_vendor_cil_for_ueventd(ext_fs, compatible_sepolicy)
