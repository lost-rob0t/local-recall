from __future__ import annotations

import json
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .errors import AuditFailure, AuditFailureCode
from .models import AuditEvent


@dataclass(frozen=True, slots=True)
class AuditFileSettings:
    root: Path
    max_file_bytes: int = 16 * 1024 * 1024
    max_files: int = 8
    max_age_days: int = 30
    fsync_each_event: bool = True
    max_event_bytes: int = 4096

    def __post_init__(self) -> None:
        if self.max_file_bytes < 4096:
            raise ValueError("max_file_bytes must be at least 4096")
        if not 1 <= self.max_files <= 1024:
            raise ValueError("max_files must be between 1 and 1024")
        if not 1 <= self.max_age_days <= 3650:
            raise ValueError("max_age_days must be between 1 and 3650")
        if not 512 <= self.max_event_bytes <= self.max_file_bytes:
            raise ValueError("max_event_bytes must be between 512 and max_file_bytes")


class OwnerOnlyAuditFileSink:
    def __init__(self, settings: AuditFileSettings) -> None:
        self._settings = settings
        self._lock = threading.RLock()
        self._root = _prepare_root(settings.root)
        self._path = self._root / "audit.jsonl"
        self._descriptor = _open_log(self._path)
        self._closed = False
        self._prune_locked()

    @property
    def path(self) -> Path:
        return self._path

    def emit(self, event: AuditEvent) -> None:
        if type(event) is not AuditEvent:
            raise AuditFailure(AuditFailureCode.INVALID_EVENT)
        encoded = _encode_event(event)
        if len(encoded) > self._settings.max_event_bytes:
            raise AuditFailure(AuditFailureCode.EVENT_TOO_LARGE)
        with self._lock:
            if self._closed:
                raise AuditFailure(AuditFailureCode.IO_FAILURE)
            try:
                current_size = os.fstat(self._descriptor).st_size
                if current_size and current_size + len(encoded) > self._settings.max_file_bytes:
                    self._rotate_locked()
                _write_all(self._descriptor, encoded)
                if self._settings.fsync_each_event:
                    os.fsync(self._descriptor)
            except AuditFailure:
                raise
            except OSError as exc:
                raise AuditFailure(AuditFailureCode.IO_FAILURE) from exc

    def emit_debug(self, event: AuditEvent) -> None:
        self.emit(event)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                os.fsync(self._descriptor)
            finally:
                os.close(self._descriptor)
                self._closed = True

    def _rotate_locked(self) -> None:
        os.fsync(self._descriptor)
        os.close(self._descriptor)
        rotated = self._root / f"audit.{uuid4().hex}.jsonl"
        os.replace(self._path, rotated)
        os.chmod(rotated, 0o600)
        _fsync_directory(self._root)
        self._descriptor = _open_log(self._path)
        self._prune_locked()

    def _prune_locked(self) -> None:
        cutoff = time.time() - self._settings.max_age_days * 86_400
        candidates: list[tuple[float, Path]] = []
        for path in self._root.glob("audit.*.jsonl"):
            info = path.lstat()
            _require_owner_regular_file(info)
            candidates.append((info.st_mtime, path))
        candidates.sort(reverse=True)
        changed = False
        for index, (modified, path) in enumerate(candidates):
            if index >= self._settings.max_files or modified < cutoff:
                path.unlink(missing_ok=True)
                changed = True
        if changed:
            _fsync_directory(self._root)


def _encode_event(event: AuditEvent) -> bytes:
    payload: dict[str, object] = {
        "schema_version": 1,
        "event_id": str(event.event_id),
        "correlation_id": str(event.correlation_id),
        "occurred_at": event.occurred_at.isoformat(),
        "category": event.category.value,
        "action": event.action.value,
        "outcome": event.outcome.value,
        "reason": event.reason.value,
    }
    if event.record_id is not None:
        payload["record_id"] = str(event.record_id)
    if event.generation is not None:
        payload["generation"] = event.generation
    if event.provider_id is not None:
        payload["provider_id"] = event.provider_id
    if event.key_version is not None:
        payload["key_version"] = event.key_version
    if event.configuration_revision_digest is not None:
        payload["configuration_revision_digest"] = event.configuration_revision_digest
    if event.key_id_digest is not None:
        payload["key_id_digest"] = event.key_id_digest
    if event.attributes:
        payload["attributes"] = dict(event.attributes)
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        + b"\n"
    )


def _prepare_root(root: Path) -> Path:
    expanded = root.expanduser()
    _reject_symlink_components(expanded)
    created = not expanded.exists()
    expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = expanded.resolve()
    info = resolved.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AuditFailure(AuditFailureCode.UNSAFE_PATH)
    _require_current_owner(info)
    if created:
        os.chmod(resolved, 0o700)
    elif stat.S_IMODE(info.st_mode) != 0o700:
        raise AuditFailure(AuditFailureCode.INSECURE_PERMISSIONS)
    return resolved


def _open_log(path: Path) -> int:
    if path.exists() or path.is_symlink():
        info = path.lstat()
        _require_owner_regular_file(info)
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise AuditFailure(AuditFailureCode.INSECURE_PERMISSIONS)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AuditFailure(AuditFailureCode.UNSAFE_PATH) from exc
    try:
        info = os.fstat(descriptor)
        _require_owner_regular_file(info)
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise AuditFailure(AuditFailureCode.INSECURE_PERMISSIONS)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise AuditFailure(AuditFailureCode.IO_FAILURE)
        written += count


def _require_owner_regular_file(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AuditFailure(AuditFailureCode.UNSAFE_PATH)
    _require_current_owner(info)


def _require_current_owner(info: os.stat_result) -> None:
    getuid = getattr(os, "getuid", None)
    if getuid is not None and info.st_uid != getuid():
        raise AuditFailure(AuditFailureCode.UNSAFE_PATH)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise AuditFailure(AuditFailureCode.UNSAFE_PATH)


def _fsync_directory(path: Path) -> None:
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
