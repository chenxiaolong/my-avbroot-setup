# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

from collections.abc import Iterable, Sequence
import dataclasses
import json
import logging
import os
from pathlib import Path
import subprocess
import unicodedata


logger = logging.getLogger(__name__)


_ALLOWED_TOOLS = frozenset({'avbroot', 'afsr', 'custota-tool'})
_MAX_PREFIX_ARGUMENTS = 32
_MAX_TOOL_ARGUMENTS = 4096
_MAX_ARGUMENT_LENGTH = 4096
_MAX_COMMAND_LENGTH = 131072
_UNSAFE_ENVIRONMENT_NAMES = frozenset({
    'BASH_ENV',
    'ENV',
    'GLIBC_TUNABLES',
    'PYTHONHOME',
    'PYTHONINSPECT',
    'PYTHONPATH',
    'PYTHONSTARTUP',
    'PYTHONWARNINGS',
    'RUST_BACKTRACE',
    'RUST_LIB_BACKTRACE',
    'RUST_LOG',
})


def _validate_arguments(
    values: Sequence[str | os.PathLike[str]],
    *,
    limit: int,
    allow_empty: bool,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > limit:
        raise ValueError('invalid external tool argument sequence')

    result: list[str] = []
    total = 0
    for value in values:
        if isinstance(value, bytes):
            raise ValueError('external tool arguments must be text')
        try:
            item = os.fspath(value)
        except TypeError as e:
            raise ValueError('external tool arguments must be text') from e
        if not isinstance(item, str):
            raise ValueError('external tool arguments must be text')
        if (not allow_empty and not item) or '\0' in item:
            raise ValueError('invalid external tool argument')
        if len(item) > _MAX_ARGUMENT_LENGTH:
            raise ValueError('external tool argument is too long')
        total += len(item) + 1
        if total > _MAX_COMMAND_LENGTH:
            raise ValueError('external tool command is too long')
        result.append(item)
    return tuple(result)


def parse_tool_runner_prefix_json(value: str) -> tuple[str, ...]:
    """Parse an exact argv prefix without shell tokenization."""
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError) as e:
        raise ValueError('tool runner prefix must be a JSON string array') from e
    if not isinstance(parsed, list) or any(
        not isinstance(item, str) for item in parsed
    ):
        raise ValueError('tool runner prefix must be a JSON string array')
    return _validate_prefix(parsed)


def _validate_prefix(
    values: Sequence[str | os.PathLike[str]],
) -> tuple[str, ...]:
    prefix = _validate_arguments(
        values,
        limit=_MAX_PREFIX_ARGUMENTS,
        allow_empty=False,
    )
    if not prefix or not Path(prefix[0]).is_absolute():
        raise ValueError('tool runner executable must be an absolute path')
    for item in prefix:
        if item == '--' or any(
            unicodedata.category(character) == 'Cc'
            for character in item
        ):
            raise ValueError('invalid external tool runner prefix argument')
    return prefix


def _sanitized_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not _is_unsafe_environment_name(name)
    }


def _is_unsafe_environment_name(name: str) -> bool:
    return name in _UNSAFE_ENVIRONMENT_NAMES or name.startswith(
        ('LD_', 'DYLD_')
    )


@dataclasses.dataclass(frozen=True)
class ToolRunner:
    """Execute allowlisted tools directly or through an exact argv prefix."""

    prefix: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if self.prefix is not None:
            validated = _validate_prefix(self.prefix)
            object.__setattr__(self, 'prefix', validated)

    def run(
        self,
        tool: str,
        arguments: Sequence[str | os.PathLike[str]],
        *,
        cwd: Path | None = None,
    ) -> None:
        if tool not in _ALLOWED_TOOLS:
            raise ValueError(f'unsupported external tool: {tool!r}')
        checked = _validate_arguments(
            arguments,
            limit=_MAX_TOOL_ARGUMENTS,
            allow_empty=True,
        )
        command = (
            [tool, *checked]
            if self.prefix is None
            else [*self.prefix, tool, '--', *checked]
        )
        if sum(len(item) + 1 for item in command) > _MAX_COMMAND_LENGTH:
            raise ValueError('external tool command is too long')
        kwargs: dict[str, object] = {}
        if cwd is not None:
            kwargs['cwd'] = cwd
        if self.prefix is not None:
            kwargs['env'] = _sanitized_environment()
        subprocess.check_call(command, **kwargs)


_tool_runner = ToolRunner()


def configure_tool_runner(
    prefix: Sequence[str] | None,
    *,
    signing_environment_names: Iterable[str | None] = (),
) -> None:
    """Select legacy execution or a validated authenticated runner prefix."""
    global _tool_runner
    # Keep bare-tool execution unchanged for compatibility. Environment
    # sanitization deliberately applies only to the authenticated prefixed
    # runner and must not be broadened here.
    if prefix is not None:
        for name in signing_environment_names:
            if name is not None and _is_unsafe_environment_name(name):
                raise ValueError(
                    'unsafe signing passphrase environment variable for '
                    f'authenticated tool runner: {name}'
                )
    _tool_runner = ToolRunner(tuple(prefix) if prefix is not None else None)


def run_tool(
    tool: str,
    arguments: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
) -> None:
    _tool_runner.run(tool, arguments, cwd=cwd)


def _run_command(
    command: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
) -> None:
    if not command or not isinstance(command[0], str):
        raise ValueError('external tool command must start with a tool name')
    run_tool(command[0], command[1:], cwd=cwd)


@dataclasses.dataclass
class SigningKey:
    key: Path
    pass_env: str | None
    pass_file: Path | None


def verify_ota(ota: Path, public_key_avb: Path | None, cert_ota: Path | None):
    logger.info(f'Verifying OTA: {ota}')

    cmd = [
        'avbroot', 'ota', 'verify',
        '--input', ota,
    ]

    if public_key_avb:
        cmd.append('--public-key-avb')
        cmd.append(public_key_avb)

    if cert_ota:
        cmd.append('--cert-ota')
        cmd.append(cert_ota)

    _run_command(cmd)


def unpack_ota(ota: Path, output_dir: Path, partitions: Iterable[str]):
    logger.info(f'Unpacking OTA: {ota}')

    cmd = [
        'avbroot', 'ota', 'extract',
        '--input', ota,
        '--directory', output_dir,
    ]

    for partition in partitions:
        cmd.append('--partition')
        cmd.append(partition)

    _run_command(cmd)


def patch_ota(
    input_ota: Path,
    output_ota: Path,
    key_avb: SigningKey,
    key_ota: SigningKey,
    cert_ota: Path,
    replace: dict[str, Path],
    extra_args: Sequence[str],
):
    image_names = ', '.join(sorted(replace.keys())) if replace else '(none)'
    logger.info(f'Patching OTA with replaced images: {image_names}: {output_ota}')

    cmd = [
        'avbroot', 'ota', 'patch',
        '--input', input_ota,
        '--output', output_ota,
        '--key-avb', key_avb.key,
        '--key-ota', key_ota.key,
        '--cert-ota', cert_ota,
        *extra_args,
    ]

    if key_avb.pass_env is not None:
        cmd.append('--pass-avb-env-var')
        cmd.append(key_avb.pass_env)
    elif key_avb.pass_file is not None:
        cmd.append('--pass-avb-file')
        cmd.append(key_avb.pass_file)

    if key_ota.pass_env is not None:
        cmd.append('--pass-ota-env-var')
        cmd.append(key_ota.pass_env)
    elif key_ota.pass_file is not None:
        cmd.append('--pass-ota-file')
        cmd.append(key_ota.pass_file)

    for k, v in replace.items():
        cmd.append('--replace')
        cmd.append(k)
        cmd.append(v)

    _run_command(cmd)


def unpack_avb(image: Path, output_dir: Path):
    logger.info(f'Unpacking AVB image: {image}')

    _run_command([
        'avbroot', 'avb', 'unpack',
        '--quiet',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_avb(
    image: Path,
    input_dir: Path,
    key: SigningKey,
    recompute_size: bool,
):
    logger.info(f'Packing AVB image: {image}')

    cmd = [
        'avbroot', 'avb', 'pack',
        '--quiet',
        '--output', image.absolute(),
        '--key', key.key.absolute(),
    ]

    if key.pass_env is not None:
        cmd.append('--pass-env-var')
        cmd.append(key.pass_env)
    elif key.pass_file is not None:
        cmd.append('--pass-file')
        cmd.append(key.pass_file.absolute())

    if recompute_size:
        cmd.append('--recompute-size')

    _run_command(cmd, cwd=input_dir)


def unpack_boot(image: Path, output_dir: Path):
    logger.info(f'Unpacking boot image: {image}')

    _run_command([
        'avbroot', 'boot', 'unpack',
        '--quiet',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_boot(image: Path, input_dir: Path):
    logger.info(f'Packing boot image: {image}')

    _run_command([
        'avbroot', 'boot', 'pack',
        '--quiet',
        '--output', image.absolute(),
    ], cwd=input_dir)


def unpack_cpio(archive: Path, output_dir: Path):
    logger.info(f'Unpacking CPIO archive: {archive}')

    _run_command([
        'avbroot', 'cpio', 'unpack',
        '--quiet',
        '--input', archive.absolute(),
    ], cwd=output_dir)


def pack_cpio(archive: Path, input_dir: Path):
    logger.info(f'Packing CPIO archive: {archive}')

    _run_command([
        'avbroot', 'cpio', 'pack',
        '--quiet',
        '--output', archive.absolute(),
    ], cwd=input_dir)


def unpack_fs(image: Path, output_dir: Path):
    logger.info(f'Unpacking filesystem: {image}')

    _run_command([
        'afsr', 'unpack',
        '--input', image.absolute(),
    ], cwd=output_dir)


def pack_fs(image: Path, input_dir: Path):
    logger.info(f'Packing filesystem: {image}')

    _run_command([
        'afsr', 'pack',
        '--output', image.absolute(),
    ], cwd=input_dir)


def generate_csig(ota: Path, key_ota: SigningKey, cert_ota: Path):
    logger.info(f'Generating Custota csig: {ota}.csig')

    cmd = [
        'custota-tool', 'gen-csig',
        '--input', ota,
        '--key', key_ota.key,
        '--cert', cert_ota,
    ]

    if key_ota.pass_env is not None:
        cmd.append('--passphrase-env-var')
        cmd.append(key_ota.pass_env)
    elif key_ota.pass_file is not None:
        cmd.append('--passphrase-file')
        cmd.append(key_ota.pass_file)

    _run_command(cmd)


def generate_update_info(update_info: Path, location: str):
    logger.info(f'Generating Custota update info: {update_info}')

    _run_command([
        'custota-tool', 'gen-update-info',
        '--file', update_info,
        '--location', location,
    ])
