# SPDX-FileCopyrightText: 2026 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import os
import platform
import subprocess
import sys
import uuid


_IS_LINUX = sys.platform == 'linux' or sys.platform == 'android'

StrPath = str | os.PathLike[str]


def _adb_run(
    cmd: list[StrPath],
    inputs: list[StrPath] = [],
    outputs: list[StrPath] = [],
    execs: list[StrPath] = [],
    **kwargs,
) -> subprocess.CompletedProcess:
    temp_files = {}

    try:
        for input in inputs:
            temp_file = f'/tmp/{uuid.uuid4()}.{os.path.basename(input)}'

            subprocess.check_call(['adb', 'push', input, temp_file])

            temp_files[input] = temp_file

        for output in outputs:
            if output in temp_files:
                continue

            temp_file = f'/tmp/{uuid.uuid4()}.{os.path.basename(output)}'
            temp_files[output] = temp_file

        for exec in execs:
            subprocess.check_call([
                'adb', 'shell',
                'chmod', '+x', temp_files[exec],
            ])

        adb_cmd = ['adb', 'shell']
        for arg in cmd:
            adb_cmd.append(temp_files.get(arg, arg))

        return subprocess.run(adb_cmd, **kwargs)

    finally:
        for output in outputs:
            temp_file = temp_files[output]
            subprocess.run(['adb', 'pull', temp_file, output])

        if temp_files:
            subprocess.run([
                'adb', 'shell',
                'rm', '-f', *temp_files.values(),
            ])


def linux_run(
    cmd: list[StrPath],
    inputs: list[StrPath] = [],
    outputs: list[StrPath] = [],
    execs: list[StrPath] = [],
):
    if _IS_LINUX:
        subprocess.check_call(cmd)
    else:
        _adb_run(cmd, inputs=inputs, outputs=outputs, execs=execs, check=True)


def linux_arch() -> str:
    if _IS_LINUX:
        return platform.machine()
    else:
        result = _adb_run(['uname', '-m'], check=True, capture_output=True)
        return result.stdout.decode('UTF-8').strip()


def linux_android_abi() -> str:
    arch = linux_arch()

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
