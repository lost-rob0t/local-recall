"""Surviving-record activity snapshot rebuild for selective deletion."""

from __future__ import annotations

import asyncio
from datetime import UTC, date, timedelta
from uuid import UUID

from local_recall.activity.reconcile import ActivityReconciler
from local_recall.activity.store import ActivitySnapshot, EncryptedActivityStore
from local_recall.domain.frames import RedactedRecord
from local_recall.ports.encryption import DecryptionRequest, EncryptionProvider
from local_recall.ports.storage import DayRangeQuery, QueryableStorageBackend

_MAX_CANDIDATE_LIMIT = 10_000
_DAY_QUERY_LIMIT = 10_000


class TimelineRebuildFailure(RuntimeError):
    """Sanitized activity rebuild failure."""


class SurvivingRecordActivityReconciler:
    """Rebuild the encrypted activity snapshot from surviving canonical records.

    Deleted records never re-enter the rebuilt snapshot because the replacement
    is regenerated exclusively from records that canonical storage still
    exposes. Decrypted records remain memory-only for the rebuild lifetime.
    """

    __slots__ = (
        "_candidate_limit",
        "_encryption",
        "_lock",
        "_reconciler",
        "_storage",
        "_store",
    )

    def __init__(
        self,
        *,
        storage: QueryableStorageBackend,
        encryption: EncryptionProvider,
        reconciler: ActivityReconciler,
        store: EncryptedActivityStore,
        candidate_limit: int = _MAX_CANDIDATE_LIMIT,
    ) -> None:
        if not 1 <= candidate_limit <= _MAX_CANDIDATE_LIMIT:
            raise ValueError("activity rebuild candidate limit is invalid")
        self._storage = storage
        self._encryption = encryption
        self._reconciler = reconciler
        self._store = store
        self._candidate_limit = candidate_limit
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        return "SurvivingRecordActivityReconciler(dependencies=redacted)"

    async def reconcile_deleted(self, record_ids: tuple[UUID, ...]) -> None:
        _validate_scope(record_ids)
        async with self._lock:
            snapshot = await self._store.load()
            if snapshot is None or not snapshot.entries:
                return
            deleted = frozenset(record_ids)
            survivors = await self._survivors(snapshot, deleted)
            await self._reconciler.reconcile(tuple(survivors))

    async def _survivors(
        self,
        snapshot: ActivitySnapshot,
        deleted: frozenset[UUID],
    ) -> tuple[RedactedRecord, ...]:
        start_day, end_day = _snapshot_window(snapshot)
        survivors: list[RedactedRecord] = []
        day = start_day
        while day <= end_day:
            candidates = await self._storage.list_candidates(
                DayRangeQuery(start_day=day, end_day=day, limit=_DAY_QUERY_LIMIT)
            )
            if len(candidates) >= _DAY_QUERY_LIMIT:
                raise TimelineRebuildFailure("activity rebuild candidate limit exceeded")
            for candidate in candidates:
                if len(survivors) >= self._candidate_limit:
                    raise TimelineRebuildFailure("activity rebuild candidate limit exceeded")
                record_id = candidate.record.record_id
                if record_id in deleted:
                    continue
                record = await self._load_survivor(record_id)
                if record is not None:
                    survivors.append(record)
            day = day + timedelta(days=1)
        return tuple(survivors)

    async def _load_survivor(self, record_id: UUID) -> RedactedRecord | None:
        envelope = await self._storage.get(record_id)
        if envelope is None:
            return None
        record = await self._encryption.decrypt(DecryptionRequest(envelope, envelope.key))
        if record.record_id != record_id:
            raise TimelineRebuildFailure("decrypted record identity mismatch")
        return record


def _validate_scope(record_ids: tuple[UUID, ...]) -> None:
    if not record_ids:
        raise ValueError("activity rebuild requires at least one record ID")
    if len(record_ids) > 10_000:
        raise ValueError("activity rebuild scope exceeds the record limit")
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("duplicate record IDs are not allowed")


def _snapshot_window(snapshot: ActivitySnapshot) -> tuple[date, date]:
    started = [entry.cluster.started_at for entry in snapshot.entries]
    ended = [entry.cluster.ended_at for entry in snapshot.entries]
    first_day = min(started).astimezone(UTC).date()
    last_day = max(ended).astimezone(UTC).date()
    if last_day < first_day:
        raise TimelineRebuildFailure("activity snapshot window is invalid")
    return first_day, last_day
