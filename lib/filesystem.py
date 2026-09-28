# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import dataclasses
import datetime
import logging
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import (
    Annotated,
    Any,
    BinaryIO,
    ClassVar,
    Iterable,
    Literal,
    TextIO,
)

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer


logger = logging.getLogger(__name__)


class EntryExists(Exception):
    pass


class ExtInstallError(ValueError):
    """A requested Ext filesystem installation is unsafe or incompatible."""


type Contexts = list[tuple[re.Pattern[str], str]]


type LinuxPath = Annotated[
    PurePosixPath,
    PlainSerializer(lambda p: str(p)),
]


type OctalMode = Annotated[
    int,
    BeforeValidator(lambda s: s if isinstance(s, int) else int(s, 8)),
    PlainSerializer(lambda m: f"{m:o}"),
]


type CpioFormat = Literal["None", "Gzip", "Lz4Legacy", "Xz"]


type CpioFileType = (
    Literal[
        "Pipe",
        "Char",
        "Directory",
        "Block",
        "Regular",
        "Symlink",
        "Socket",
        "Reserved",
    ]
    | int
)


type CpioDateTime = Annotated[
    datetime.datetime,
    PlainSerializer(lambda dt: dt.timestamp()),
]


class CpioEntry(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

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
    "RegularFile",
    "Directory",
    "CharDevice",
    "BlockDevice",
    "Fifo",
    "Socket",
    "Symlink",
]


type ExtDateTime = Annotated[
    datetime.datetime,
    PlainSerializer(lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")),
]


class ExtEntry(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

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
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    # AFSR 2.0 moved filesystem-level fields under a generic metadata object.
    # Keep the payload opaque here: PixeneOS only consumes the entry list.
    metadata: dict[str, Any]
    entries: list[ExtEntry] = []


type ExtInstallFileType = Literal["Directory", "RegularFile"]
type ExtInstallStatus = Literal["created", "already-identical"]


@dataclasses.dataclass(frozen=True)
class ExtInstallRequest:
    """One fully specified entry in an atomic-preflight installation batch."""

    path: str | os.PathLike[str]
    file_type: ExtInstallFileType
    file_mode: int
    uid: int
    gid: int
    data: bytes | None = None


@dataclasses.dataclass(frozen=True)
class ExtInstallResult:
    path: PurePosixPath
    status: ExtInstallStatus


@dataclasses.dataclass(frozen=True)
class _ExtInstallPlanEntry:
    request: ExtInstallRequest
    path: PurePosixPath
    tree_path: Path
    label: str
    status: ExtInstallStatus


@dataclasses.dataclass
class ExtFs:
    info: ExtInfo
    tree: Path
    contexts: Contexts

    def _get_paths(
        self,
        path: str | os.PathLike[str],
    ) -> tuple[PurePosixPath, Path]:
        root_path = PurePosixPath("/")
        abs_path = root_path.joinpath(path)
        rel_path = abs_path.relative_to(root_path)
        tree_path = self.tree / rel_path

        return abs_path, tree_path

    def _find(self, path: PurePosixPath) -> ExtEntry | None:
        # Linear searches are fast enough.
        return next((e for e in self.info.entries if e.path == path), None)

    def _install_path(
        self,
        path: str | os.PathLike[str],
    ) -> tuple[PurePosixPath, Path]:
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str):
            raise ExtInstallError("installation paths must be text")
        if (
            not raw_path
            or "\0" in raw_path
            or "\\" in raw_path
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in raw_path
            )
        ):
            raise ExtInstallError(f"invalid installation path: {raw_path!r}")

        parsed = PurePosixPath(raw_path)
        if not parsed.is_absolute() or parsed.anchor != "/":
            raise ExtInstallError(
                f"installation path must have one absolute root: {raw_path!r}",
            )
        if ".." in parsed.parts:
            raise ExtInstallError(
                f"installation path contains a parent component: {raw_path!r}",
            )
        # PurePosixPath intentionally normalizes '.', repeated separators, and
        # trailing separators. Refuse aliases instead of letting two different
        # spellings address the same output path.
        if str(parsed) != raw_path:
            raise ExtInstallError(
                f"installation path is not canonical: {raw_path!r}",
            )

        abs_path, tree_path = self._get_paths(parsed)
        if abs_path == PurePosixPath("/"):
            raise ExtInstallError("the filesystem root cannot be installed")

        return abs_path, tree_path

    def _install_label(self, path: PurePosixPath) -> str:
        path_str = str(path)
        try:
            return next(
                label for pattern, label in self.contexts if pattern.fullmatch(path_str)
            )
        except StopIteration:
            raise ExtInstallError(
                f"no file_contexts label matches installation path: {path}",
            ) from None

    @staticmethod
    def _validate_install_request(request: ExtInstallRequest):
        if request.file_type not in ("Directory", "RegularFile"):
            raise ExtInstallError(
                f"unsupported installation entry type: {request.file_type!r}",
            )
        for field, value in (
            ("file_mode", request.file_mode),
            ("uid", request.uid),
            ("gid", request.gid),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ExtInstallError(f"{field} must be a non-negative integer")
        if request.file_mode > 0o7777:
            raise ExtInstallError("file_mode contains non-permission bits")
        if request.file_type == "Directory" and request.data is not None:
            raise ExtInstallError("directory installation entries cannot have data")
        if request.file_type == "RegularFile" and not isinstance(request.data, bytes):
            raise ExtInstallError("regular-file installation entries require bytes")

    @staticmethod
    def _tree_file_type(metadata: os.stat_result) -> ExtFileType | None:
        mode = metadata.st_mode
        if stat.S_ISREG(mode):
            return "RegularFile"
        if stat.S_ISDIR(mode):
            return "Directory"
        if stat.S_ISCHR(mode):
            return "CharDevice"
        if stat.S_ISBLK(mode):
            return "BlockDevice"
        if stat.S_ISFIFO(mode):
            return "Fifo"
        if stat.S_ISSOCK(mode):
            return "Socket"
        if stat.S_ISLNK(mode):
            return "Symlink"
        return None

    def _validate_tree_entry(self, entry: ExtEntry, tree_path: Path):
        try:
            metadata = tree_path.lstat()
        except FileNotFoundError:
            raise ExtInstallError(
                f"metadata/tree disagreement: {entry.path} is missing from tree",
            ) from None

        actual_type = self._tree_file_type(metadata)
        if actual_type != entry.file_type:
            raise ExtInstallError(
                "metadata/tree disagreement: "
                f"{entry.path} is {entry.file_type} in metadata but "
                f"{actual_type or 'an unknown type'} in tree",
            )

    @staticmethod
    def _directory_open_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

    def _open_tree_directory(self, path: PurePosixPath) -> int:
        """Open a tree directory without following any namespace symlinks."""

        descriptor = os.open(self.tree, self._directory_open_flags())
        try:
            for component in path.parts[1:]:
                child = os.open(
                    component,
                    self._directory_open_flags(),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _open_install_parent(self, path: PurePosixPath) -> tuple[int, str]:
        try:
            return self._open_tree_directory(path.parent), path.name
        except OSError as exc:
            raise ExtInstallError(
                f"installation parent changed or is unsafe: {path.parent}",
            ) from exc

    def _install_file_matches(self, path: PurePosixPath, expected: bytes) -> bool:
        parent_fd, name = self._open_install_parent(path)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ExtInstallError(
                    f"installation path changed or is unsafe: {path}",
                )
            if metadata.st_size != len(expected):
                return False
            offset = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                end = offset + len(chunk)
                if chunk != expected[offset:end]:
                    return False
                offset = end
            return offset == len(expected)
        except OSError as exc:
            raise ExtInstallError(
                f"installation path changed or is unsafe: {path}",
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)

    @staticmethod
    def _parents(path: PurePosixPath) -> Iterable[PurePosixPath]:
        parent = path.parent
        while True:
            yield parent
            if parent == PurePosixPath("/"):
                break
            parent = parent.parent

    def _preflight_install(
        self,
        requests: Iterable[ExtInstallRequest],
    ) -> list[_ExtInstallPlanEntry]:
        request_list = list(requests)
        metadata_by_path: dict[PurePosixPath, ExtEntry] = {}
        for metadata_entry in self.info.entries:
            if metadata_entry.path in metadata_by_path:
                raise ExtInstallError(
                    f"duplicate filesystem metadata entry: {metadata_entry.path}",
                )
            metadata_by_path[metadata_entry.path] = metadata_entry

        planned: dict[PurePosixPath, tuple[ExtInstallRequest, Path, str]] = {}
        for request in request_list:
            if not isinstance(request, ExtInstallRequest):
                raise TypeError("install entries must be ExtInstallRequest instances")
            self._validate_install_request(request)
            path, tree_path = self._install_path(request.path)
            if path in planned:
                raise ExtInstallError(f"duplicate installation path: {path}")
            planned[path] = (request, tree_path, self._install_label(path))

        # Validate every touched namespace component against both representations.
        touched = set(planned)
        for path in planned:
            touched.update(self._parents(path))

        for path in sorted(touched, key=str):
            existing_entry = metadata_by_path.get(path)
            planned_entry = planned.get(path)
            _, tree_path = self._get_paths(path)

            if existing_entry is not None:
                self._validate_tree_entry(existing_entry, tree_path)
            elif tree_path.is_symlink() or tree_path.exists():
                raise ExtInstallError(
                    f"metadata/tree disagreement: {path} exists only in tree",
                )

            if path == PurePosixPath("/"):
                if existing_entry is None or existing_entry.file_type != "Directory":
                    raise ExtInstallError(
                        "filesystem root is missing or is not a directory",
                    )
                continue

            if path not in planned:
                if existing_entry is None:
                    raise ExtInstallError(f"missing installation parent: {path}")
                if existing_entry.file_type != "Directory":
                    raise ExtInstallError(
                        f"installation parent is not a directory: {path}",
                    )
                continue

            assert planned_entry is not None
            request = planned_entry[0]
            # Every planned entry that has children must itself be a directory.
            if any(child.parent == path for child in planned) and (
                request.file_type != "Directory"
            ):
                raise ExtInstallError(
                    f"planned installation parent is not a directory: {path}",
                )

        plan: list[_ExtInstallPlanEntry] = []
        for path, (request, tree_path, label) in planned.items():
            existing = metadata_by_path.get(path)
            status: ExtInstallStatus = "created"
            if existing is not None:
                expected_xattr = f"{label}\0"
                identical = (
                    existing.file_type == request.file_type
                    and existing.file_mode == request.file_mode
                    and existing.uid == request.uid
                    and existing.gid == request.gid
                    and existing.xattrs
                    == {
                        "security.selinux": expected_xattr,
                    }
                )
                if identical and request.file_type == "RegularFile":
                    assert request.data is not None
                    identical = self._install_file_matches(path, request.data)
                if not identical:
                    raise EntryExists(
                        f"installation path collides with different content or metadata: {path}",
                    )
                status = "already-identical"

            plan.append(
                _ExtInstallPlanEntry(
                    request=request,
                    path=path,
                    tree_path=tree_path,
                    label=label,
                    status=status,
                )
            )

        return sorted(plan, key=lambda item: str(item.path))

    def preflight_install(
        self,
        requests: Iterable[ExtInstallRequest],
    ) -> list[ExtInstallResult]:
        """Validate a complete batch without changing metadata or tree contents."""

        return [
            ExtInstallResult(path=item.path, status=item.status)
            for item in self._preflight_install(requests)
        ]

    def install(
        self,
        requests: Iterable[ExtInstallRequest],
    ) -> list[ExtInstallResult]:
        """Preflight and install a complete batch of directories and files."""

        request_list = list(requests)
        plan = self._preflight_install(request_list)
        additions = [item for item in plan if item.status == "created"]

        # Recheck existing requested files through no-follow directory handles.
        # This closes the gap between path-based preflight and mutation if an
        # unpacked tree is changed concurrently.
        for item in plan:
            if item.status != "already-identical":
                continue
            if item.request.file_type == "RegularFile":
                assert item.request.data is not None
                if not self._install_file_matches(item.path, item.request.data):
                    raise EntryExists(
                        f"installation path changed after preflight: {item.path}",
                    )
            else:
                try:
                    descriptor = self._open_tree_directory(item.path)
                except OSError as exc:
                    raise ExtInstallError(
                        f"installation path changed or is unsafe: {item.path}",
                    ) from exc
                else:
                    os.close(descriptor)

        # Parents must be materialized before children, regardless of request order.
        additions.sort(key=lambda item: (len(item.path.parts), str(item.path)))
        new_metadata: list[ExtEntry] = []
        metadata_by_path = {entry.path: entry for entry in self.info.entries}
        # Retain one parent handle per path until the entire batch completes so
        # an ordinary write/fsync failure can remove every tree entry it made.
        parent_handles: dict[PurePosixPath, int] = {}
        created: list[_ExtInstallPlanEntry] = []

        def parent_handle(path: PurePosixPath) -> tuple[int, str]:
            parent_path = path.parent
            try:
                return parent_handles[parent_path], path.name
            except KeyError:
                descriptor, name = self._open_install_parent(path)
                parent_handles[parent_path] = descriptor
                return descriptor, name

        try:
            for item in additions:
                request = item.request
                parent = metadata_by_path[item.path.parent]
                parent_fd, name = parent_handle(item.path)
                if request.file_type == "Directory":
                    os.mkdir(name, request.file_mode, dir_fd=parent_fd)
                    created.append(item)
                    child_fd = os.open(
                        name,
                        self._directory_open_flags(),
                        dir_fd=parent_fd,
                    )
                    try:
                        os.fchmod(child_fd, request.file_mode)
                        os.fsync(child_fd)
                    finally:
                        os.close(child_fd)
                else:
                    assert request.data is not None
                    descriptor = os.open(
                        name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        request.file_mode,
                        dir_fd=parent_fd,
                    )
                    created.append(item)
                    try:
                        os.fchmod(descriptor, request.file_mode)
                        view = memoryview(request.data)
                        while view:
                            written = os.write(descriptor, view)
                            if written == 0:
                                raise OSError("short write while installing file")
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                os.fsync(parent_fd)

                logger.info(
                    f"Adding {request.file_type} filesystem entry: {item.path}",
                )
                entry = ExtEntry(
                    path=item.path,
                    source=None,
                    file_type=request.file_type,
                    file_mode=request.file_mode,
                    uid=request.uid,
                    gid=request.gid,
                    atime=parent.atime,
                    ctime=parent.ctime,
                    mtime=parent.mtime,
                    crtime=parent.crtime,
                    device_major=None,
                    device_minor=None,
                    symlink_target=None,
                    xattrs={"security.selinux": f"{item.label}\0"},
                )
                new_metadata.append(entry)
                metadata_by_path[item.path] = entry
        except BaseException as exc:
            rollback_errors: list[OSError] = []
            for item in reversed(created):
                parent_fd = parent_handles[item.path.parent]
                try:
                    if item.request.file_type == "Directory":
                        os.rmdir(item.path.name, dir_fd=parent_fd)
                    else:
                        os.unlink(item.path.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError as rollback_exc:
                    rollback_errors.append(rollback_exc)
            if rollback_errors:
                exc.add_note(
                    "filesystem install rollback encountered "
                    f"{len(rollback_errors)} error(s)",
                )
            raise
        finally:
            for parent_fd in parent_handles.values():
                os.close(parent_fd)

        # A preflight failure cannot reach this mutation point. Publish metadata
        # only after all tree writes complete, so consumers never observe partial
        # ExtInfo updates.
        self.info.entries.extend(new_metadata)

        return [ExtInstallResult(path=item.path, status=item.status) for item in plan]

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

        logger.info(f"Adding {file_type} filesystem entry: {path}")

        label = self._install_label(path)

        # Inherit uid, gid, and timestamps from the parent.
        self.info.entries.append(
            ExtEntry(
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
                    "security.selinux": f"{label}\0",
                },
            )
        )

    def mkdir(
        self,
        path: str | os.PathLike[str],
        mode: int = 0o755,
        parents: bool = False,
        exist_ok: bool = False,
    ):
        abs_path, _ = self._get_paths(path)

        try:
            self._add_entry(abs_path, "Directory", mode)
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

        if "w" in open_mode or "a" in open_mode or "x" in open_mode:
            try:
                self._add_entry(abs_path, "RegularFile", mode)
            except EntryExists:
                if "x" in open_mode:
                    raise

            # The parent exists in the entries, so make sure it exists in the
            # filesystem too. `afsr unpack` does not create empty directories
            # and neither do we in mkdir().
            tree_path.parent.mkdir(parents=True, exist_ok=True)

        return tree_path.open(open_mode)


def load_file_contexts(path: Path) -> Contexts:
    whitespace = re.compile(r"\s+")
    result: Contexts = []

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            pieces = whitespace.split(line)
            if len(pieces) == 2:
                regex = pieces[0]
                label = pieces[1]
            elif len(pieces) == 3 and pieces[1] == "--":
                regex = pieces[0]
                label = pieces[2]
            else:
                raise ValueError(f"Invalid file_contexts line: {line}")

            result.append((re.compile(regex), label))

    return result
