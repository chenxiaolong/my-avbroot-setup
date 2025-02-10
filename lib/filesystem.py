# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import dataclasses
import datetime
import logging
import os
from pathlib import Path, PurePosixPath
import re
from typing import Annotated, BinaryIO, ClassVar, Literal, TextIO, override

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer


logger = logging.getLogger(__name__)


class EntryExists(Exception):
    pass


type Contexts = list[tuple[re.Pattern[str], str]]


type LinuxPath = Annotated[
    PurePosixPath,
    PlainSerializer(lambda p: str(p)),
]


type OctalMode = Annotated[
    int,
    BeforeValidator(lambda s: s if isinstance(s, int) else int(s, 8)),
    PlainSerializer(lambda m: f'{m:o}'),
]


type CpioFormat = Literal['None', 'Gzip', 'Lz4Legacy', 'Xz']


type CpioFileType = Literal[
    'Pipe',
    'Char',
    'Directory',
    'Block',
    'Regular',
    'Symlink',
    'Socket',
    'Reserved',
] | int


type CpioDateTime = Annotated[
    datetime.datetime,
    PlainSerializer(lambda dt: dt.timestamp()),
]


class CpioEntry(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra='forbid')

    path: LinuxPath
    data: str | None = None
    inode: int | None = None
    file_type: CpioFileType
    file_mode: OctalMode | None = None
    uid: int | None = None
    gid: int | None = None
    nlink: int | None = None
    mtime: CpioDateTime | None = None
    dev_maj: int | None = None
    dev_min: int | None = None
    rdev_maj: int | None = None
    rdev_min: int | None = None
    crc32: int | None = None


class CpioInfo(BaseModel):
    format: CpioFormat
    entries: list[CpioEntry]


@dataclasses.dataclass
class CpioFs:
    info: CpioInfo
    tree: Path

    # There are currently no filesystem operations implemented here because we
    # don't need them yet.


type ExtFileType = Literal[
    'RegularFile',
    'Directory',
    'CharDevice',
    'BlockDevice',
    'Fifo',
    'Socket',
    'Symlink',
]


type ExtDateTime = Annotated[
    datetime.datetime,
    PlainSerializer(lambda dt: dt.strftime('%Y-%m-%dT%H:%M:%SZ')),
]


class ExtEntry(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra='forbid')

    path: LinuxPath
    source: Path | None = None
    file_type: ExtFileType
    file_mode: OctalMode | None = None
    uid: int | None = None
    gid: int | None = None
    atime: ExtDateTime | None = None
    ctime: ExtDateTime | None = None
    mtime: ExtDateTime | None = None
    crtime: ExtDateTime | None = None
    device_major: int | None = None
    device_minor: int | None = None
    symlink_target: str | None = None
    xattrs: dict[str, str] = {}


class ExtInfo(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra='forbid')

    features: list[str]
    block_size: int
    reserved_percentage: int
    inode_size: int | None = None
    uuid: str
    directory_hash_seed: str | None = None
    volume_name: str | None = None
    last_mounted_on: str | None = None
    creation_time: str | None = None
    entries: list[ExtEntry] = []


@dataclasses.dataclass
class ExtFs:
    info: ExtInfo
    tree: Path
    contexts: Contexts

    def _get_paths(
        self,
        path: str | os.PathLike[str],
    ) -> tuple[PurePosixPath, Path]:
        root_path = PurePosixPath('/')
        abs_path = root_path.joinpath(path)
        rel_path = abs_path.relative_to(root_path)
        tree_path = self.tree / rel_path

        return abs_path, tree_path

    def _find(self, path: PurePosixPath) -> ExtEntry | None:
        # Linear searches are fast enough.
        return next((e for e in self.info.entries if e.path == path), None)

    def _add_entry(
        self,
        path: PurePosixPath,
        file_type: ExtFileType,
        mode: int,
    ):
        if self._find(path):
            raise EntryExists(path)

        parent = path.parent
        assert parent != path

        parent_entry = self._find(parent)
        if not parent_entry:
            raise FileNotFoundError(parent)

        logger.info(f'Adding {file_type} filesystem entry: {path}')

        path_str = str(path)
        label = next(c[1] for c in self.contexts if c[0].fullmatch(path_str))

        # Inherit uid, gid, and timestamps from the parent.
        self.info.entries.append(ExtEntry(
            path=path,
            source=None,
            file_type=file_type,
            file_mode=mode,
            uid=parent_entry.uid if parent_entry else None,
            gid=parent_entry.gid if parent_entry else None,
            atime=parent_entry.atime if parent_entry else None,
            ctime=parent_entry.ctime if parent_entry else None,
            mtime=parent_entry.mtime if parent_entry else None,
            crtime=parent_entry.crtime if parent_entry else None,
            device_major=None,
            device_minor=None,
            symlink_target=None,
            xattrs={
                'security.selinux': f'{label}\0',
            },
        ))

    def mkdir(
        self,
        path: str | os.PathLike[str],
        mode: int = 0o755,
        parents: bool = False,
        exist_ok: bool = False,
    ):
        abs_path, _ = self._get_paths(path)

        try:
            self._add_entry(abs_path, 'Directory', mode)
        except FileNotFoundError:
            if not parents or abs_path.parent == abs_path:
                raise

            self.mkdir(abs_path.parent, mode, parents=True, exist_ok=True)
            self.mkdir(abs_path, mode, parents=False, exist_ok=exist_ok)
        except EntryExists:
            if not exist_ok:
                raise

    def open(
        self,
        path: str | os.PathLike[str],
        open_mode: str,
        mode: int = 0o644,
    ) -> BinaryIO | TextIO:
        abs_path, tree_path = self._get_paths(path)

        if 'w' in open_mode or 'a' in open_mode or 'x' in open_mode:
            try:
                self._add_entry(abs_path, 'RegularFile', mode)
            except EntryExists:
                if 'x' in open_mode:
                    raise

            # The parent exists in the entries, so make sure it exists in the
            # filesystem too. `afsr unpack` does not create empty directories
            # and neither do we in mkdir().
            tree_path.parent.mkdir(parents=True, exist_ok=True)

        return tree_path.open(open_mode)


def load_file_contexts(path: Path) -> Contexts:
    whitespace = re.compile(r'\s+')
    result: Contexts = []

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
