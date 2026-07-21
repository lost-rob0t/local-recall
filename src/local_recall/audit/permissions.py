from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import AuditFailure, AuditFailureCode


@dataclass(frozen=True, slots=True)
class PermissionValidationReport:
    directories: int
    files: int

    def __post_init__(self) -> None:
        if self.directories < 0 or self.files < 0:
            raise ValueError("permission validation counts must be non-negative")


def validate_owner_only_storage_tree(root: Path) -> PermissionValidationReport:
    expanded = root.expanduser()
    if not expanded.exists() and not expanded.is_symlink():
        return PermissionValidationReport(0, 0)
    _reject_symlink_components(expanded)
    resolved = expanded.resolve()
    root_info = resolved.lstat()
    _require_directory(root_info)
    directories = 1
    files = 0
    for current, directory_names, file_names in os.walk(resolved, followlinks=False):
        current_path = Path(current)
        current_info = current_path.lstat()
        _require_directory(current_info)
        for name in directory_names:
            path = current_path / name
            info = path.lstat()
            _require_directory(info)
            directories += 1
        for name in file_names:
            path = current_path / name
            info = path.lstat()
            _require_file(info)
            files += 1
    return PermissionValidationReport(directories, files)


def _require_directory(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AuditFailure(AuditFailureCode.UNSAFE_PATH)
    _require_current_owner(info)
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise AuditFailure(AuditFailureCode.INSECURE_PERMISSIONS)


def _require_file(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AuditFailure(AuditFailureCode.UNSAFE_PATH)
    _require_current_owner(info)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise AuditFailure(AuditFailureCode.INSECURE_PERMISSIONS)


def _require_current_owner(info: os.stat_result) -> None:
    getuid = getattr(os, "getuid", None)
    if getuid is not None and info.st_uid != getuid():
        raise AuditFailure(AuditFailureCode.UNSAFE_PATH)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise AuditFailure(AuditFailureCode.UNSAFE_PATH)
