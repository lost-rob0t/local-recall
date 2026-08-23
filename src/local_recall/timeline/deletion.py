"""Crash-recoverable selective deletion orchestration."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

from local_recall.ports.storage import DeleteRequest, DeleteResult

_JOURNAL_NAME = "deletion-intent.json"
_JOURNAL_VERSION = 1
_MAX_JOURNAL_BYTES = 64 * 1024


class DeletionPhase(StrEnum):
    PLANNED = "planned"
    RECORDS_DELETED = "records-deleted"
    DERIVED_RECONCILED = "derived-reconciled"


@dataclass(frozen=True, slots=True)
class DeletionState:
    request_id: str
    record_ids: tuple[UUID, ...]
    phase: DeletionPhase

    def __post_init__(self) -> None:
        _validate_request_id(self.request_id)
        _validate_record_ids(self.record_ids)


@dataclass(frozen=True, slots=True)
class DeletionTransactionResult:
    request_id: str
    deleted_count: int
    recovered: bool


class DeletionStorage(Protocol):
    async def delete(self, request: DeleteRequest) -> DeleteResult: ...


class DeletionSemanticIndex(Protocol):
    async def remove(self, record_ids: tuple[UUID, ...]) -> object: ...


class ActivityDeletionReconciler(Protocol):
    async def reconcile_deleted(self, record_ids: tuple[UUID, ...]) -> None: ...


class DeletionJournal:
    def __init__(self, root: Path) -> None:
        self._root = root
        self._path = root / _JOURNAL_NAME
        self._prepare_root()
        self._lock = asyncio.Lock()

    async def begin(self, request_id: str, record_ids: tuple[UUID, ...]) -> DeletionState:
        state = DeletionState(request_id, record_ids, DeletionPhase.PLANNED)
        async with self._lock:
            current = await asyncio.to_thread(self._load_sync)
            if current is not None:
                if current.request_id != request_id or current.record_ids != record_ids:
                    raise RuntimeError("another deletion transaction is already in progress")
                return current
            await asyncio.to_thread(self._write_sync, state)
        return state

    async def load(self) -> DeletionState | None:
        async with self._lock:
            return await asyncio.to_thread(self._load_sync)

    async def advance(self, phase: DeletionPhase) -> DeletionState:
        async with self._lock:
            current = await asyncio.to_thread(self._load_sync)
            if current is None:
                raise RuntimeError("deletion transaction is not active")
            if _phase_rank(phase) < _phase_rank(current.phase):
                raise RuntimeError("deletion transaction cannot move backward")
            if _phase_rank(phase) > _phase_rank(current.phase) + 1:
                raise RuntimeError("deletion transaction phase transition is invalid")
            replacement = DeletionState(current.request_id, current.record_ids, phase)
            await asyncio.to_thread(self._write_sync, replacement)
            return replacement

    async def clear(self) -> None:
        async with self._lock:
            await asyncio.to_thread(self._clear_sync)

    def _prepare_root(self) -> None:
        if self._root.exists():
            info = self._root.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("deletion journal root must be a real directory")
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("deletion journal root must be owner-only")
            return
        self._root.mkdir(parents=True, mode=0o700)

    def _load_sync(self) -> DeletionState | None:
        if not self._path.exists():
            return None
        info = self._path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("deletion journal file is unsafe")
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("deletion journal file must be owner-only")
        if info.st_size <= 0 or info.st_size > _MAX_JOURNAL_BYTES:
            raise RuntimeError("deletion journal file has an invalid size")
        try:
            raw = cast(dict[str, object], json.loads(self._path.read_bytes()))
            if set(raw) != {"phase", "record_ids", "request_id", "version"}:
                raise ValueError
            if raw["version"] != _JOURNAL_VERSION:
                raise ValueError
            raw_ids = raw["record_ids"]
            if not isinstance(raw_ids, list) or not all(isinstance(item, str) for item in raw_ids):
                raise ValueError
            request_id = raw["request_id"]
            phase = raw["phase"]
            if not isinstance(request_id, str) or not isinstance(phase, str):
                raise ValueError
            return DeletionState(
                request_id=request_id,
                record_ids=tuple(UUID(cast(str, item)) for item in raw_ids),
                phase=DeletionPhase(phase),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("deletion journal is invalid") from exc

    def _write_sync(self, state: DeletionState) -> None:
        payload = json.dumps(
            {
                "phase": state.phase.value,
                "record_ids": [str(record_id) for record_id in state.record_ids],
                "request_id": state.request_id,
                "version": _JOURNAL_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(payload) > _MAX_JOURNAL_BYTES:
            raise ValueError("deletion journal exceeds the size limit")
        temporary = self._path.with_name(f".{self._path.name}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(payload)
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            os.fsync(descriptor)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            os.close(descriptor)
        os.replace(temporary, self._path)
        _fsync_directory(self._root)

    def _clear_sync(self) -> None:
        if not self._path.exists():
            return
        info = self._path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("deletion journal file is unsafe")
        self._path.unlink()
        _fsync_directory(self._root)


class DeletionCoordinator:
    def __init__(
        self,
        *,
        journal: DeletionJournal,
        storage: DeletionStorage,
        semantic_index: DeletionSemanticIndex,
        activity_reconciler: ActivityDeletionReconciler,
    ) -> None:
        self._journal = journal
        self._storage = storage
        self._semantic_index = semantic_index
        self._activity_reconciler = activity_reconciler
        self._lock = asyncio.Lock()

    async def delete(
        self,
        *,
        request_id: str,
        record_ids: tuple[UUID, ...],
    ) -> DeletionTransactionResult:
        _validate_request_id(request_id)
        _validate_record_ids(record_ids)
        async with self._lock:
            state = await self._journal.begin(request_id, record_ids)
            return await self._resume(state, recovered=False)

    async def recover(self) -> DeletionTransactionResult | None:
        async with self._lock:
            state = await self._journal.load()
            if state is None:
                return None
            return await self._resume(state, recovered=True)

    async def _resume(
        self,
        state: DeletionState,
        *,
        recovered: bool,
    ) -> DeletionTransactionResult:
        if state.phase is DeletionPhase.PLANNED:
            for record_id in state.record_ids:
                await self._storage.delete(DeleteRequest(record_id, "selective-delete"))
            state = await self._journal.advance(DeletionPhase.RECORDS_DELETED)

        if state.phase is DeletionPhase.RECORDS_DELETED:
            await self._semantic_index.remove(state.record_ids)
            await self._activity_reconciler.reconcile_deleted(state.record_ids)
            state = await self._journal.advance(DeletionPhase.DERIVED_RECONCILED)

        if state.phase is DeletionPhase.DERIVED_RECONCILED:
            await self._journal.clear()

        return DeletionTransactionResult(
            request_id=state.request_id,
            deleted_count=len(state.record_ids),
            recovered=recovered,
        )


def _validate_request_id(request_id: str) -> None:
    if not 1 <= len(request_id) <= 128:
        raise ValueError("request_id must be between 1 and 128 characters")
    if not all(
        character.isascii() and (character.isalnum() or character in "-_")
        for character in request_id
    ):
        raise ValueError("request_id must be an opaque ASCII identifier")


def _validate_record_ids(record_ids: tuple[UUID, ...]) -> None:
    if not record_ids:
        raise ValueError("deletion requires at least one record ID")
    if len(record_ids) > 10_000:
        raise ValueError("deletion scope exceeds the record limit")
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("duplicate record IDs are not allowed")


def _phase_rank(phase: DeletionPhase) -> int:
    return {
        DeletionPhase.PLANNED: 0,
        DeletionPhase.RECORDS_DELETED: 1,
        DeletionPhase.DERIVED_RECONCILED: 2,
    }[phase]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
