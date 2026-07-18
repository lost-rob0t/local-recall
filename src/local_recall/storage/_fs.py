from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import UUID

from .errors import StorageFailure, StorageFailureCode


@dataclass(frozen=True, slots=True)
class StoragePaths:
    root: Path
    resolved_root: Path
    blobs: Path
    quarantine: Path
    catalog: Path


def prepare_paths(root_directory: str | Path) -> StoragePaths:
    root = Path(root_directory)
    reject_symlink_components(root)
    prepare_owner_directory(root)
    resolved_root = root.resolve(strict=True)
    blobs = root / "blobs"
    quarantine = root / "quarantine"
    prepare_owner_directory(blobs)
    prepare_owner_directory(quarantine)
    catalog = root / "catalog.sqlite3"
    prepare_owner_file(catalog)
    return StoragePaths(root, resolved_root, blobs, quarantine, catalog)


def blob_token(record_id: UUID) -> str:
    value = record_id.hex
    return f"blobs/{value[:2]}/{value}.lre"


def temporary_token(record_id: UUID) -> str:
    value = record_id.hex
    return f"blobs/{value[:2]}/.{value}.tmp-{secrets.token_hex(8)}"


def safe_path(paths: StoragePaths, token: str | None) -> Path:
    if token is None:
        raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE)
    relative = PurePosixPath(token)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE)
    candidate = paths.root.joinpath(*relative.parts)
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(paths.resolved_root):
        raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE)
    return candidate


def write_exclusive(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(value)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def matches_digest(path: Path, expected_size: int, expected_digest: bytes) -> bool:
    try:
        value = path.read_bytes()
    except OSError:
        return False
    return len(value) == expected_size and secrets.compare_digest(
        hashlib.sha256(value).digest(),
        expected_digest,
    )


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare_owner_directory(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("storage directory must be a real directory")
    else:
        path.mkdir(parents=True, mode=0o700)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("storage directory must be owner-only")


def prepare_owner_file(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError("storage catalog must be a regular file")
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("storage catalog must be owner-only")


def reject_symlink_components(path: Path) -> None:
    current = path
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise ValueError("storage paths must not contain symlinks")
        current = current.parent
