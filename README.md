# My avbroot setup

This repo describes my personal setup for modifying the OS on my Android devices.

Unlike the norm in the Android modding community, I do not use runtime modifications and instead, prefer to modify the Android image directly. This eliminates the need for privileged code to live on writable storage and avoids giving potential malware a place to persist.

This repo includes the script I use for modifying Android OTAs. Folks should probably not use the script as-is and instead, adapt it to their needs.

## Requirements

* Linux
    * Needed for running a statically-linked Android executable
* python3
* [python3-tomlkit](https://pypi.org/project/tomlkit/)
* [avbroot](https://github.com/chenxiaolong/avbroot) (>= version 3.3.0)
* [afsr](https://github.com/chenxiaolong/afsr) (>= commit adcae036b68684828edf5eb90be1500abd5cf491)
* [Custota](https://github.com/chenxiaolong/Custota) (>= version 4.5)
* [MSD](https://github.com/chenxiaolong/MSD)
* [BCR](https://github.com/chenxiaolong/BCR) (>= version 1.65)
* [OEMUnlockOnBoot](https://github.com/chenxiaolong/OEMUnlockOnBoot) (>= version 1.1)
* [AlterInstaller](https://github.com/chenxiaolong/AlterInstaller) (>= version 2.0)

The `avbroot`, `afsr`, and `custota-tool` commands must exist in `PATH`.

## Usage

```bash
python3 patch.py \
    --input ota.zip \
    --verify-public-key-avb verify_avb_pkmd.bin \
    --verify-cert-ota verify_ota.crt \
    --sign-key-avb sign_avb.key \
    --sign-key-ota sign_ota.key \
    --sign-cert-ota sign_cert.key \
    --module-custota Custota-<version>-release.zip \
    --module-msd MSD-<version>-release.zip \
    --module-bcr BCR-<version>-release.zip \
    --module-oemunlockonboot OEMUnlockOnBoot-<version>-release.zip \
    --module-alterinstaller AlterInstaller-<version>-release.zip
```

This will:

1. Verify the original OTA signatures against the specified verification keys. This includes the OTA signature, the `payload.bin` signature, and the signatures of every AVB-enabled partition image.
2. Extract the `system`, `vendor`, and `vendor_boot` partitions. This is all done in userspace. Root access is not needed as nothing is ever mounted by the kernel.
3. Verify the signatures of BCR and the other modules and copy the necessary files. Commands that would traditionally be run during boot via the module's `service.sh` and `post-fs-data.sh` scripts are added as proper init services.
4. Repack the `system`, `vendor`, and `vendor_boot` partitions, re-signing them with the specified AVB key if necessary.
5. Patch the OTA using avbroot's `--rootless` mode, replacing the 3 modified partitions. This will re-sign other partitions (eg. `vbmeta`) needed to reestablish AVB's chain of trust and also sign the patched OTA.
6. Generate the metadata needed to install the OTA using Custota.

## Why not root?

When folks refer to "rooting" in the Android community, they're usually not just referring to a process running as UID 0. The term generally also includes the functionality for making runtime code patches (eg. with Zygisk) and making runtime filesystem modifications (eg. Magisk modules).

### UID 0

This is probably where my usage differs from most. I use root access purely for reverse engineering and debugging. As long as I can run a process as UID 0 via adb, that's good enough for me. I don't allow any Android apps to gain root access. In the past, I used my own soft-fork of Magisk with the relevant code and SELinux rules that allows such access completely removed.

Out of the many root-enabled apps I've studied or reverse engineered, the vast majority fail to handle arbitrary inputs properly (especially filenames). For example, some root-supporting file managers turn a seemingly benign action like listing a directory into local privilege escalation. This is trivially exploitable, especially with browsers auto-downloading files with server-provided filenames to `/sdcard/Download/`.

To avoid repeated root access UI prompts, some apps spawn a long-running shell session, write commands to stdin, and rely on parsing stdout and searching for the shell prompt to determine when commands complete. This approach is prone to desync, which can lead to commands being skipped or other inputs being interpreted as commands.

All in all, I simply do not trust most root-enabled apps to not leave a gaping security hole, so I avoid them entirely. There are apps that do handle root access in what I would consider a more proper way, by spawning a daemon as root and then talking to the daemon over a well defined binary protocol. Unfortunately, this approach is the extreme minority.

For situations where I actually do need to run a process as UID 0, I use Android's official way of getting root access: `adb root` and `/system/xbin/su`. To accomplish that, I make a `userdebug` build of GrapheneOS and set the `ro.adb.secure=1` property to retain adb's host key verification:

```diff
--- a/build/core/main.mk
+++ b/build/core/main.mk
@@ -397,9 +397,9 @@ ifneq (,$(user_variant))
   # default is 2000 ms as of Android 14.
   ADDITIONAL_SYSTEM_PROPERTIES += ro.sys.time_detector_update_diff=50

-  ifeq ($(user_variant),user)
     ADDITIONAL_SYSTEM_PROPERTIES += ro.adb.secure=1
-  endif

   ifeq ($(user_variant),userdebug)
     # Pick up some extra useful tools
```

### Runtime code patching

In the past, I used Zygisk + LSPosed for one reason only: to disable Android 12+'s verified links "feature". With GrapheneOS, I no longer have a use for this because the functionality can effectively be disabled by [removing the network permission from the `Intent Filter Verification Service` system app](https://grapheneos.org/usage#app-link-verification). This also means I no longer need to flip between enabling and disabling Zygisk because it conflicts with some debugger functionality.

### Modules

This is, by far, the main reason I "rooted" my device in the past. I've written several apps that only require system app privileges, not root, but Magisk modules are the easiest and most convenient way to install them. Modules allow running scripts during boot and overriding arbitrary filesystem paths via bind mounts (or overlayfs). Unfortunately, while this is incredibly convenient, it also makes it easy for potential malware to persist.

I wanted to have a way to install system apps without breaking Android's security model. My initial thought was to modify Magisk so that it would only load modules from the AVB-protected boot image ramdisk. Since I no longer used Magisk's other functionality, I didn't end up pursuing this approach. Instead, I wrote afsr to make it easy to unpack, modify, and repack ext2/3/4 images (byte-for-byte reproducibly). This way, I can add system apps in a way that preserves the guarantees of Android Verified Boot.

I could accomplish the exact same result by adding the apps I care about to the AOSP build system when building GrapheneOS. I intentionally don't do that because the iteration time for building OTAs with AOSP's build system is so long even when nothing has changed.

### Root detection, SafetyNet, Play Integrity

Apps that do these things don't remain installed on my devices :)

## License

This repo is licensed under GPLv3. Please see [`LICENSE`](./LICENSE) for the full license text.
