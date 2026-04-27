# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson, 2025 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only
"""
SELinux CIL rules for my-avbroot-setup modules.
These rules are used for direct CIL patching when precompiled policies are not available.
This is primarily for LineageOS compatibility.
"""

# Custota SELinux CIL Rules
# These rules allow the Custota app to perform OTA updates
CUSTOTA_CIL_RULES = [
    "; Custota SELinux rules for CIL patching",
    "; These rules are appended to CIL policy files for ROMs without precompiled sepolicy",
    "",
    "; Type declarations (will be created if they do not exist)",
    "(type custota_app)",
    "(type custota_app_userfaultfd)",
    "",
    "; Allow custota_app to access OTA package files",
    "(allow custota_app ota_package_file (dir (add_name getattr ioctl lock open read remove_name search watch watch_reads write)))",
    "(allow custota_app ota_package_file (file (append create getattr ioctl lock map open read rename setattr unlink watch watch_reads write)))",
    "",
    "; Binder communication with update_engine",
    "(allow custota_app update_engine (binder (call transfer)))",
    "(allow update_engine custota_app (binder (call transfer)))",
    "(allow custota_app update_engine (fd (use)))",
    "(allow update_engine custota_app (fd (use)))",
    "",
    "; Service manager access",
    "(allow custota_app update_engine_service (service_manager (find)))",
    "(allow custota_app oem_lock_service (service_manager (find)))",
    "",
    "; Allow update_engine to access FUSE files for OTA from internal storage",
    "(allow update_engine mediaprovider_app (fd (use)))",
    "(allow update_engine fuse (file (getattr read)))",
    "(allow update_engine sdcardfs (file (getattr read)))",
    "(allow update_engine media_rw_data_file (file (getattr read)))",
]

# MSD (Mass Storage Device) SELinux CIL Rules
# These rules allow the MSD daemon to provide USB mass storage functionality
MSD_CIL_RULES = [
    "; MSD SELinux rules for CIL patching",
    "; These rules are appended to CIL policy files for ROMs without precompiled sepolicy",
    "",
    "; Type declarations",
    "(type msd_app)",
    "(type msd_app_userfaultfd)",
    "(type msd_daemon)",
    "",
    "; msd_daemon domain attributes",
    "(roletype r msd_daemon)",
    "(typeattributeset domain (msd_daemon))",
    "(typeattributeset mlstrustedsubject (msd_daemon))",
    "",
    "; Allow daemon to execute system binaries",
    "(allow msd_daemon system_file (file (entrypoint execute map read)))",
    "",
    "; init transition to daemon",
    "(allow init msd_daemon (process (transition)))",
    "(allow init msd_daemon (process (rlimitinh siginh)))",
    "",
    "; Required capabilities for privilege dropping",
    "(allow msd_daemon msd_daemon (capability (chown setgid setuid)))",
    "",
    "; Allow daemon to read SELinux status",
    "(allow msd_daemon selinuxfs (file (open read)))",
    "",
    "; Allow daemon to find USB gadget HAL in /proc",
    "(allow msd_daemon hal_usb_gadget_impl (dir (search)))",
    "(allow msd_daemon hal_usb_gadget_impl (file (read)))",
    "(allow msd_daemon hal_usb_gadget_impl (lnk_file (read)))",
    "",
    "; Signal handling for USB gadget HAL",
    "(allow msd_daemon hal_usb_gadget_impl (process (sigstop signal)))",
    "",
    "; ConfigFS access for USB gadget configuration",
    "(allow msd_daemon configfs (dir (add_name create open read remove_name rmdir search setattr write)))",
    "(allow msd_daemon configfs (file (create getattr open read setattr write)))",
    "(allow msd_daemon configfs (lnk_file (create read setattr unlink)))",
    "; Samsung-specific configfs type",
    "(allow msd_daemon usb_configfs (dir (add_name create open read remove_name rmdir search setattr write)))",
    "(allow msd_daemon usb_configfs (file (create getattr open read setattr write)))",
    "(allow msd_daemon usb_configfs (lnk_file (create read setattr unlink)))",
    "",
    "; Property access",
    "(allow msd_daemon storage_config_prop (file (getattr map open read)))",
    "(allow msd_daemon usb_control_prop (file (getattr map open read)))",
    "",
    "; FUSE filesystem access for file serving",
    "(allow msd_daemon mediaprovider (fd (use)))",
    "(allow msd_daemon platform_app (fd (use)))",
    "(allow msd_daemon mediaprovider_app (fd (use)))",
    "",
    "; Storage file access (FUSE, sdcardfs, SD cards)",
    "(allow msd_daemon fuse (file (getattr read open write)))",
    "(allow msd_daemon sdcardfs (file (getattr read open write)))",
    "(allow msd_daemon media_rw_data_file (file (getattr read open write)))",
    "(allow msd_daemon vfat (file (getattr read open write)))",
    "(allow msd_daemon exfat (file (getattr read open write)))",
    "",
    "; Kernel FD access",
    "(allow kernel msd_daemon (fd (use)))",
    "",
    "; Unix socket for client-daemon communication",
    "(blockinherit unix_socket)\n(allow msd_app msd_daemon (unix_stream_socket (connectto)))",
    "",
    "; Block daemon from connecting to itself (used for policy verification)",
    "(neverallow msd_daemon msd_daemon (unix_stream_socket (connectto)))",
]

# Map module names to their CIL rules
MODULE_CIL_RULES = {
    "custota": CUSTOTA_CIL_RULES,
    "msd": MSD_CIL_RULES,
}


def get_cil_rules(module_name: str) -> list[str]:
    """
    Get CIL rules for a specific module.

    Args:
        module_name: Name of the module (custota, msd, etc.)

    Returns:
        List of CIL rule strings
    """
    return MODULE_CIL_RULES.get(module_name, [])
