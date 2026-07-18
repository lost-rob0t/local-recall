from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from .errors import StorageFailure, StorageFailureCode


@dataclass(frozen=True, slots=True)
class StoragePaths:
    root: Path
    blobs: Path
    temporary: Path
    quarantine: Path
    catalog: Path


def prepare_paths(root: Path) -> StoragePaths:
    expanded = root.expanduser()
    _reject_symlink_components(expanded)
    expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
    ensure_directory(expanded)
    resolved = expanded.resolve()
    paths = StoragePaths(
        root=resolved,
        blobs=resolved / "blobs",
        temporary=resolved / "tmp",
        quarantine=resolved / "quarantine",
        catalog=resolved / "catalog.sqlite3",
    )
    for directory in (paths.blobs, paths.temporary, paths.quarantine):
        if directory.exists() and directory.is_symlink():
            raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
        directory.mkdir(mode=0o700, exist_ok=True)
        ensure_directory(directory)
    if paths.catalog.exists() and (paths.catalog.is_symlink() or not paths.catalog.is_file()):
        raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
    return paths


def blob_token(record_id: UUID) -> str:
    if record_id.version != 4:
        raise StorageFailure(StorageFailureCode.INVALID_RECORD_ID, record_id=record_id)
    value = record_id.hex
    return f"{value[:2]}/{value}.lre"


def blob_path(paths: StoragePaths, token: str) -> Path:
    parts = token.split("/")
    if len(parts) != 2:
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    shard, name = parts
    stem = name.removesuffix(".lre")
    if (
        len(shard) != 2
        or len(stem) != 32
        or name != f"{stem}.lre"
        or any(character not in "0123456789abcdef" for character in shard + stem)
    ):
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    base = paths.blobs.resolve()
    parent = paths.blobs / shard
    if parent.exists():
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise StorageFailure(StorageFailureCode.CORRUPTION)
        require_current_owner(info)
    if parent.resolve() != base / shard:
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    return parent / name


def read_blob(paths: StoragePaths, token: str, maximum: int) -> bytes:
    return read_regular_file(blob_path(paths, token), maximum)


def read_regular_file(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StorageFailure(StorageFailureCode.CORRUPTION) from exc
    try:
        info = os.fstat(descriptor)
        require_current_owner(info)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > maximum:
            raise StorageFailure(StorageFailureCode.CORRUPTION)
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise StorageFailure(StorageFailureCode.CORRUPTION)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise StorageFailure(StorageFailureCode.CORRUPTION)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_blob_atomically(
    paths: StoragePaths,
    token: str,
    blob: bytes,
    fault: Callable[[str], None],
) -> None:
    final = blob_path(paths, token)
    final.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ensure_directory(final.parent)
    if final.exists() or final.is_symlink():
        raise StorageFailure(StorageFailureCode.DUPLICATE_RECORD)
    temporary = paths.temporary / f"{uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(blob)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fault("after_temp_fsync")
    os.replace(temporary, final)
    os.chmod(final, 0o600)
    fsync_directory(final.parent)


def quarantine_path(paths: StoragePaths, path: Path) -> bool:
    if not path.exists():
        return False
    target = paths.quarantine / f"{uuid4().hex}.lrq"
    os.replace(path, target)
    os.chmod(target, 0o600)
    fsync_directory(paths.quarantine)
    return True


def iter_blob_files(paths: StoragePaths) -> Iterator[Path]:
    for shard in paths.blobs.iterdir():
        info = shard.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
        require_current_owner(info)
        for path in shard.iterdir():
            path_info = path.lstat()
            if stat.S_ISLNK(path_info.st_mode):
                raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
            require_current_owner(path_info)
            if stat.S_ISREG(path_info.st_mode) and path.suffix == ".lre":
                yield path


def content_bytes_on_disk(paths: StoragePaths) -> int:
    total = 0
    for root in (paths.blobs, paths.temporary, paths.quarantine):
        for path in root.rglob("*"):
            if path.is_symlink():
                raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
            if path.is_file():
                info = path.stat(follow_symlinks=False)
                require_current_owner(info)
                total += info.st_size
    return total


def ensure_catalog_permissions(paths: StoragePaths) -> None:
    candidates = (
        paths.catalog,
        *(Path(f"{paths.catalog}{suffix}") for suffix in ("-wal", "-shm", "-journal")),
    )
    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.is_symlink() or not candidate.is_file():
            raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
        require_current_owner(candidate.stat(follow_symlinks=False))
        os.chmod(candidate, 0o600)


def safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_directory(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
    require_current_owner(info)
    os.chmod(path, 0o700)


def require_current_owner(info: os.stat_result) -> None:
    getuid = getattr(os, "getuid", None)
    if getuid is not None and info.st_uid != getuid():
        raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
