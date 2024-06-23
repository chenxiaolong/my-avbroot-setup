#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import argparse
import dataclasses
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tomlkit
from typing import assert_never, Iterable, Match, Pattern, Tuple
import zipfile


TIMESTAMP = '2009-01-01T00:00:00Z'

# https://codeberg.org/chenxiaolong/chenxiaolong
# https://gitlab.com/chenxiaolong/chenxiaolong
# https://github.com/chenxiaolong/chenxiaolong
SSH_PUBLIC_KEY_CHENXIAOLONG = \
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOe6/tBnO7xZhAWXRj3ApUYgn+XZ0wnQiXM8B7tPgv4'


def status(*args, **kwargs):
    if 'file' not in kwargs:
        kwargs['file'] = sys.stderr

    print(f'\x1b[1m[*] {' '.join(args)}\x1b[0m', **kwargs)


def verify_ota(ota: Path, public_key_avb: Path, cert_ota: Path):
    status(f'Verifying OTA: {ota}')

    subprocess.check_call([
        'avbroot', 'ota', 'verify',
        '--input', ota,
        '--public-key-avb', public_key_avb,
        '--cert-ota', cert_ota,
    ])


def unpack_ota(ota: Path, output_dir: Path, all: bool):
    status(f'Unpacking OTA: {ota}')

    cmd = [
        'avbroot', 'ota', 'extract',
        '--input', ota,
        '--directory', output_dir,
    ]

    if all:
        cmd.append('--all')

    subprocess.check_call(cmd)


def patch_ota(
    input_ota: Path,
    output_ota: Path,
    key_avb: Path,
    key_ota: Path,
    cert_ota: Path,
    replace: dict[str, Path],
):
    image_names = ', '.join(sorted(replace.keys()))
    status(f'Patching OTA with replaced images: {image_names}: {output_ota}')

    cmd = [
        'avbroot', 'ota', 'patch',
        '--input', input_ota,
        '--output', output_ota,
        '--key-avb', key_avb,
        '--key-ota', key_ota,
        '--cert-ota', cert_ota,
        '--rootless',
    ]

    for k, v in replace.items():
        cmd.append('--replace')
        cmd.append(k)
        cmd.append(v)

    subprocess.check_call(cmd)


def unpack_avb(image: Path, output_dir: Path):
    status(f'Unpacking AVB image: {image}')

    subprocess.check_call([
        'avbroot', 'avb', 'unpack',
        '--quiet',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_avb(image: Path, input_dir: Path, key: Path, recompute_size: bool):
    status(f'Packing AVB image: {image}')

    cmd = [
        'avbroot', 'avb', 'pack',
        '--quiet',
        '--output', image.absolute(),
        '--key', key,
    ]

    if recompute_size:
        cmd.append('--recompute-size')

    subprocess.check_call(cmd, cwd=input_dir)


def unpack_boot(image: Path, output_dir: Path):
    status(f'Unpacking boot image: {image}')

    subprocess.check_call([
        'avbroot', 'boot', 'unpack',
        '--quiet',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_boot(image: Path, input_dir: Path):
    status(f'Packing boot image: {image}')

    subprocess.check_call([
        'avbroot', 'boot', 'pack',
        '--quiet',
        '--output', image.absolute(),
    ], cwd=input_dir)


def unpack_cpio(archive: Path, output_dir: Path):
    status(f'Unpacking CPIO archive: {archive}')

    subprocess.check_call([
        'avbroot', 'cpio', 'unpack',
        '--quiet',
        '--input', archive.absolute(),
    ], cwd=output_dir)


def pack_cpio(archive: Path, input_dir: Path):
    status(f'Packing CPIO archive: {archive}')

    subprocess.check_call([
        'avbroot', 'cpio', 'pack',
        '--quiet',
        '--output', archive.absolute(),
    ], cwd=input_dir)


def unpack_fs(image: Path, output_dir: Path):
    status(f'Unpacking filesystem: {image}')

    subprocess.check_call([
        'afsr', 'unpack',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_fs(image: Path, input_dir: Path):
    status(f'Packing filesystem: {image}')

    subprocess.check_call([
        'afsr', 'pack',
        '--output', image.absolute(),
    ], cwd=input_dir)


def generate_csig(ota: Path, key_ota: Path, cert_ota: Path):
    status(f'Generating Custota csig: {ota}.csig')

    subprocess.check_call([
        'custota-tool', 'gen-csig',
        '--input', ota,
        '--key', key_ota,
        '--cert', cert_ota,
    ])


def get_ota_metadata(ota: Path) -> dict[str, str]:
    props = {}

    with zipfile.ZipFile(ota, 'r') as z:
        with z.open('META-INF/com/android/metadata', 'r') as f:
            for line in f:
                line = line.decode('UTF-8').strip()

                key, delim, value = line.partition('=')
                if not delim:
                    raise ValueError(f'Bad OTA metadata line: {line!r}')

                props[key] = value

    return props


def generate_update_info(update_info: Path, location: str):
    status(f'Generating Custota update info: {update_info}')

    subprocess.check_call([
        'custota-tool', 'gen-update-info',
        '--file', update_info,
        '--location', location,
    ])


type Contexts = list[Tuple[Pattern[str], str]]


def load_file_contexts(path: Path) -> Contexts:
    whitespace = re.compile(r'\s+')
    result = []

    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            pieces = whitespace.split(line)
            if len(pieces) == 2:
                regex = pieces[0]
                label = pieces[1]
            elif len(pieces) == 3 and pieces[1] == '--':
                regex = pieces[0]
                label = pieces[2]
            else:
                raise ValueError(f'Invalid file_contexts line: {line}')

            result.append((re.compile(regex), label))

    return result


class EntryExists(Exception):
    pass


def add_entry(
    entries: list,
    contexts: Contexts,
    path: str,
    file_type: str,
    mode: int,
):
    assert path.startswith('/')

    # Linear searches are fast enough.
    if any(e['path'] == path for e in entries):
        raise EntryExists(path)

    status(f'Adding {file_type} filesystem entry: {path}')

    label = next(c[1] for c in contexts if c[0].fullmatch(path))

    entries.append({
        'path': path,
        'file_type': file_type,
        'file_mode': f'{mode:o}',
        'atime': TIMESTAMP,
        'ctime': TIMESTAMP,
        'mtime': TIMESTAMP,
        'crtime': TIMESTAMP,
        'xattrs': {
            'security.selinux': f'{label}\0',
        },
    })


def add_file_entry(
    entries: list,
    contexts: Contexts,
    path: str,
    mode: int,
    create_parents: bool = True,
):
    if create_parents:
        for parent in PurePosixPath(path).parents:
            try:
                add_entry(entries, contexts, str(parent), 'Directory', 0o755)
            except EntryExists:
                pass

    add_entry(entries, contexts, path, 'RegularFile', mode)


@dataclasses.dataclass
class InitScript:
    name: str
    command: list[str]
    class_: str | None = None
    seclabel: str | None = None
    env: dict[str, str] = dataclasses.field(default_factory=dict)
    condition: str | None = None
    blocking: bool = False

    @staticmethod
    def _escape(token: str) -> str:
        def replacement(match: Match[str]) -> str:
            value = match.group(1)

            if value == '\n':
                return r'\n'
            elif value == '\r':
                return r'\r'
            elif value == '\t':
                return r'\t'
            elif value == '\\':
                return r'\\'
            elif value == ' ':
                # We additionally escape spaces instead of adding double quotes.
                return r'\ '
            else:
                assert_never(value)

        return re.sub(r'(\n\r\t\\ )', replacement, token)

    def __str__(self) -> str:
        name_escaped = self._escape(self.name)
        command_escaped = ' '.join(self._escape(arg) for arg in self.command)

        lines = [
            f'service {name_escaped} {command_escaped}',
            '    oneshot',
        ]

        if self.class_:
            lines.append(f'    class {self._escape(self.class_)}')

        if self.seclabel:
            lines.append(f'    seclabel {self._escape(self.seclabel)}')

        for k, v in self.env.items():
            lines.append(f'    setenv {self._escape(k)} {self._escape(v)}')

        if self.condition:
            lines.append('    disabled')
            lines.append('')
            # This is intentionally an unescaped raw string so that we don't
            # have to use an AST to represent boolean conditions.
            lines.append(f'on {self.condition}')
            if self.blocking:
                lines.append(f'    exec_start {name_escaped}')
            else:
                lines.append(f'    start {name_escaped}')

        lines.append('')

        return '\n'.join(lines)


def add_init_script(
    script: InitScript,
    entries: list,
    tree: Path,
    contexts: Contexts,
):
    assert '/' not in script.name
    path = f'system/etc/init/{script.name}.rc'

    add_file_entry(entries, contexts, f'/{path}', 0o644)

    with open(tree / path, 'w') as f:
        f.write(str(script))


def zip_extract(zip: zipfile.ZipFile, name: str, output: Path):
    with zip.open(name, 'r') as f_in:
        with open(output, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)


def verify_ssh_sig(zip: Path, sig: Path, public_key: str):
    status(f'Verifying SSH signature: {zip}')

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


def inject_custota(
    module_zip: Path,
    module_sig: Path,
    entries: list,
    tree: Path,
    contexts: Contexts,
    sepolicies: Iterable[Path],
):
    verify_ssh_sig(module_zip, module_sig, SSH_PUBLIC_KEY_CHENXIAOLONG)

    status(f'Injecting Custota: {module_zip}')

    with zipfile.ZipFile(module_zip, 'r') as z:
        apk = None

        for path in z.namelist():
            if not path.endswith('.apk') and not path.endswith('.xml'):
                continue
            elif path.endswith('.apk'):
                apk = path

            # Add to filesystem entries.
            add_file_entry(entries, contexts, f'/{path}', 0o644)

            # Extract file contents.
            tree_path = tree / path
            tree_path.parent.mkdir(parents=True, exist_ok=True)
            zip_extract(z, path, tree_path)

        assert apk

        arch = platform.machine()
        if arch == 'arm64':
            abi = 'arm64-v8a'
        else:
            abi = arch

        # Add SELinux rules.
        with tempfile.NamedTemporaryFile(delete_on_close=False) as f_temp:
            with (
                z.open(apk, 'r') as f_apk,
                zipfile.ZipFile(f_apk, 'r') as z_apk,
                z_apk.open(f'lib/{abi}/libcustota_selinux.so', 'r') as f_exe,
            ):
                shutil.copyfileobj(f_exe, f_temp)
                os.fchmod(f_temp.fileno(), 0o700)

            f_temp.close()

            for sepolicy in sepolicies:
                status(f'Adding Custota SELinux rules: {sepolicy}')

                subprocess.check_call([
                    f_temp.name,
                    '--source', sepolicy,
                    '--target', sepolicy,
                ])

    seapp = tree / 'system' / 'etc' / 'selinux' / 'plat_seapp_contexts'
    status(f'Adding Custota seapp context: {seapp}')

    with open(seapp, 'a') as f_temp:
        f_temp.write(
            'user=_app '
            'isPrivApp=true '
            'name=com.chiller3.custota '
            'domain=custota_app '
            'type=app_data_file '
            'levelFrom=all\n'
        )


def inject_bcr(
    module_zip: Path,
    module_sig: Path,
    entries: list,
    tree: Path,
    contexts: Contexts,
):
    verify_ssh_sig(module_zip, module_sig, SSH_PUBLIC_KEY_CHENXIAOLONG)

    status(f'Injecting BCR: {module_zip}')

    apk = None

    with zipfile.ZipFile(module_zip, 'r') as z:
        for path in z.namelist():
            if not path.endswith('.apk') and not path.endswith('.xml'):
                continue
            elif path.endswith('.apk'):
                apk = path

            # Add to filesystem entries.
            add_file_entry(entries, contexts, f'/{path}', 0o644)

            # Extract file contents.
            tree_path = tree / path
            tree_path.parent.mkdir(parents=True, exist_ok=True)
            zip_extract(z, path, tree_path)

    assert apk

    add_init_script(
        InitScript(
            name='bcr_remove_hard_restrictions',
            command=[
                '/system/bin/app_process',
                '/',
                'com.chiller3.bcr.standalone.RemoveHardRestrictionsKt',
            ],
            class_='main',
            seclabel='u:r:su:s0',
            env={
                'CLASSPATH': f'/{apk}',
            },
        ),
        entries,
        tree,
        contexts,
    )


def inject_oemunlockonboot(
    module_zip: Path,
    module_sig: Path,
    entries: list,
    tree: Path,
    contexts: Contexts,
):
    verify_ssh_sig(module_zip, module_sig, SSH_PUBLIC_KEY_CHENXIAOLONG)

    status(f'Injecting OEMUnlockOnBoot: {module_zip}')

    with zipfile.ZipFile(module_zip, 'r') as z:
        apk = next(n for n in z.namelist() if n.endswith('.apk'))
        # Intentionally put it somewhere that won't be picked up by Android's
        # package manager since it's not really an app and the apk is unsigned.
        path = 'system/bin/oemunlockonboot.apk'

        # Add to filesystem entries.
        add_file_entry(entries, contexts, f'/{path}', 0o644)

        # Extract file contents.
        tree_path = tree / path
        tree_path.parent.mkdir(parents=True, exist_ok=True)
        zip_extract(z, apk, tree_path)

    add_init_script(
        InitScript(
            name='oemunlockonboot',
            command=[
                '/system/bin/app_process',
                '/',
                'com.chiller3.oemunlockonboot.Main',
            ],
            class_='main',
            seclabel='u:r:su:s0',
            env={
                'CLASSPATH': f'/{path}',
            },
        ),
        entries,
        tree,
        contexts,
    )


def inject_alterinstaller(
    module_zip: Path,
    module_sig: Path,
    entries: list,
    tree: Path,
    contexts: Contexts,
):
    verify_ssh_sig(module_zip, module_sig, SSH_PUBLIC_KEY_CHENXIAOLONG)

    status(f'Injecting AlterInstaller: {module_zip}')

    with zipfile.ZipFile(module_zip, 'r') as z:
        apk = next(n for n in z.namelist() if n.endswith('.apk'))
        # Intentionally put it somewhere that won't be picked up by Android's
        # package manager since it's not really an app and the apk is unsigned.
        path = 'system/bin/alterinstaller.apk'

        # Add to filesystem entries.
        add_file_entry(entries, contexts, f'/{path}', 0o644)

        # Extract file contents.
        tree_path = tree / path
        tree_path.parent.mkdir(parents=True, exist_ok=True)
        zip_extract(z, apk, tree_path)

    add_init_script(
        InitScript(
            name='alterinstaller_backup',
            command=[
                '/system/bin/cp',
                '/data/system/packages.xml',
                '/data/local/tmp/AlterInstaller.backup.xml',
            ],
            class_='main',
            seclabel='u:r:su:s0',
            # This must run and exit before the package manager starts.
            condition='post-fs-data',
            blocking=True,
        ),
        entries,
        tree,
        contexts,
    )

    add_init_script(
        InitScript(
            name='alterinstaller_exec',
            command=[
                '/system/bin/app_process',
                '/',
                'com.chiller3.alterinstaller.Main',
                '/data/local/tmp/AlterInstaller.properties',
                '/data/system/packages.xml',
                '/data/system/packages.xml',
            ],
            class_='main',
            seclabel='u:r:su:s0',
            env={
                'CLASSPATH': f'/{path}',
            },
            # This must run and exit before the package manager starts.
            condition='post-fs-data',
            blocking=True,
        ),
        entries,
        tree,
        contexts,
    )


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--input',
        type=Path,
        required=True,
        help='Input OTA',
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='Output OTA',
    )
    parser.add_argument(
        '--verify-public-key-avb',
        type=Path,
        required=True,
        help='AVB public key for verifying input OTA',
    )
    parser.add_argument(
        '--verify-cert-ota',
        type=Path,
        required=True,
        help='OTA certificate for verifying input OTA',
    )
    parser.add_argument(
        '--sign-key-avb',
        type=Path,
        required=True,
        help='AVB private key for signing output OTA',
    )
    parser.add_argument(
        '--sign-key-ota',
        type=Path,
        required=True,
        help='OTA private key for signing output OTA',
    )
    parser.add_argument(
        '--sign-cert-ota',
        type=Path,
        required=True,
        help='OTA certificate for signing output OTA',
    )
    parser.add_argument(
        '--module-bcr',
        type=Path,
        required=True,
        help='BCR module zip',
    )
    parser.add_argument(
        '--module-bcr-sig',
        type=Path,
        help='BCR module zip signature',
    )
    parser.add_argument(
        '--module-custota',
        type=Path,
        required=True,
        help='Custota module zip',
    )
    parser.add_argument(
        '--module-custota-sig',
        type=Path,
        help='Custota module zip signature',
    )
    parser.add_argument(
        '--module-oemunlockonboot',
        type=Path,
        required=True,
        help='OEMUnlockOnBoot module zip',
    )
    parser.add_argument(
        '--module-oemunlockonboot-sig',
        type=Path,
        help='OEMUnlockOnBoot module zip signature',
    )
    parser.add_argument(
        '--module-alterinstaller',
        type=Path,
        required=True,
        help='AlterInstaller module zip',
    )
    parser.add_argument(
        '--module-alterinstaller-sig',
        type=Path,
        help='AlterInstaller module zip signature',
    )
    parser.add_argument(
        '--debug-shell',
        action='store_true',
        help='Spawn a debug shell before cleaning up temporary directory',
    )

    args = parser.parse_args()

    if args.output is None:
        args.output = Path(f'{args.input}.patched')
    if args.module_bcr_sig is None:
        args.module_bcr_sig = Path(f'{args.module_bcr}.sig')
    if args.module_custota_sig is None:
        args.module_custota_sig = Path(f'{args.module_custota}.sig')
    if args.module_oemunlockonboot_sig is None:
        args.module_oemunlockonboot_sig = \
            Path(f'{args.module_oemunlockonboot}.sig')
    if args.module_alterinstaller_sig is None:
        args.module_alterinstaller_sig = \
            Path(f'{args.module_alterinstaller}.sig')

    return args


def run(args: argparse.Namespace, temp_dir: Path):
    images_dir = temp_dir / 'images'

    system_image = images_dir / 'system.img'
    system_dir = temp_dir / 'system'
    system_raw = system_dir / 'raw.img'
    system_metadata = system_dir / 'fs_metadata.toml'
    system_tree = system_dir / 'fs_tree'

    vendor_image = images_dir / 'vendor.img'
    vendor_dir = temp_dir / 'vendor'
    vendor_raw = vendor_dir / 'raw.img'
    vendor_tree = vendor_dir / 'fs_tree'

    vendor_boot_image = images_dir / 'vendor_boot.img'
    vendor_boot_dir = temp_dir / 'vendor_boot'
    vendor_boot_raw = vendor_boot_dir / 'raw.img'
    vendor_boot_ramdisk = vendor_boot_dir / 'ramdisk.img.0'
    vendor_boot_tree = vendor_boot_dir / 'cpio_tree'

    # Verify OTA.
    verify_ota(args.input, args.verify_public_key_avb, args.verify_cert_ota)

    # Unpack OTA.
    unpack_ota(args.input, images_dir, True)

    # Unpack system image.
    system_dir.mkdir()
    unpack_avb(system_image, system_dir)
    unpack_fs(system_raw, system_dir)
    with open(system_metadata, 'rb') as f:
        system_fs_info = tomlkit.load(f)

    # Parse SELinux label mappings for use when creating new entries.
    system_contexts = load_file_contexts(
        system_tree / 'system' / 'etc' / 'selinux' / 'plat_file_contexts')

    # Unpack vendor image.
    vendor_dir.mkdir()
    unpack_avb(vendor_image, vendor_dir)
    unpack_fs(vendor_raw, vendor_dir)

    # Unpack vendor_boot image.
    vendor_boot_dir.mkdir()
    unpack_avb(vendor_boot_image, vendor_boot_dir)
    unpack_boot(vendor_boot_raw, vendor_boot_dir)
    unpack_cpio(vendor_boot_ramdisk, vendor_boot_dir)

    # Inject modules.
    inject_custota(
        args.module_custota,
        args.module_custota_sig,
        system_fs_info['entries'],
        system_tree,
        system_contexts,
        # We only update the precompiled policies and leave the CIL policies
        # alone. Since we're starting from a (hopefully) properly built Android
        # build, we should never run into a situation where the precompiled
        # sepolicy is out of date and needs to be recompiled from the CIL files
        # during boot.
        [
            vendor_tree / 'etc' / 'selinux' / 'precompiled_sepolicy',
            vendor_boot_tree / 'sepolicy',
        ],
    )
    inject_bcr(
        args.module_bcr,
        args.module_bcr_sig,
        system_fs_info['entries'],
        system_tree,
        system_contexts,
    )
    inject_oemunlockonboot(
        args.module_oemunlockonboot,
        args.module_oemunlockonboot_sig,
        system_fs_info['entries'],
        system_tree,
        system_contexts,
    )
    inject_alterinstaller(
        args.module_alterinstaller,
        args.module_alterinstaller_sig,
        system_fs_info['entries'],
        system_tree,
        system_contexts,
    )

    # Repack system image.
    with open(system_metadata, 'w') as f:
        tomlkit.dump(system_fs_info, f)
    pack_fs(system_raw, system_dir)
    pack_avb(system_image, system_dir, args.sign_key_avb, True)

    # Repack vendor image.
    pack_fs(vendor_raw, vendor_dir)
    pack_avb(vendor_image, vendor_dir, args.sign_key_avb, True)

    # Repack vendor_boot image.
    pack_cpio(vendor_boot_ramdisk, vendor_boot_dir)
    pack_boot(vendor_boot_raw, vendor_boot_dir)
    pack_avb(vendor_boot_image, vendor_boot_dir, args.sign_key_avb, False)

    # Patch OTA.
    patch_ota(
        args.input,
        args.output,
        args.sign_key_avb,
        args.sign_key_ota,
        args.sign_cert_ota,
        {
            'system': system_image,
            'vendor': vendor_image,
            'vendor_boot': vendor_boot_image,
        },
    )

    # Generate Custota csig.
    generate_csig(args.output, args.sign_key_ota, args.sign_cert_ota)

    # Generate Custota update-info.
    codename = get_ota_metadata(args.output)['pre-device']
    update_info = args.output.parent / f'{codename}.json'
    generate_update_info(update_info, args.output.name)


def main():
    args = parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            run(args, Path(temp_dir))
        finally:
            if args.debug_shell:
                shell = os.getenv('SHELL', 'bash')
                status(f'Debug shell: {shell}')
                subprocess.run([shell], cwd=temp_dir)


if __name__ == '__main__':
    main()
