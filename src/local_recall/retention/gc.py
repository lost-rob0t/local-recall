"""Idempotent garbage collection reconciling derived state with canonical storage."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from local_recall.activity.store import EncryptedActivityStore
from local_recall.audit.recorder import AuditRecorder
from local_recall.index.semantic import EncryptedSemanticIndex
from local_recall.retention.planner import RetentionStorage
from local_recall.timeline.activity_rebuild import SurvivingRecordActivityReconciler


@dataclass(frozen=True, slots=True)
class GarbageCollectionResult:
    pruned_index_entries: int
    rebuilt_activity: bool


class GarbageCollector:
    """Reconcile encrypted derived snapshots with canonical storage.

    Every step recomputes from canonical state and is idempotent, so an
    interrupted collection resumes safely by simply running again. Canonical
    storage is never modified by the collector.
    """

    def __init__(
        self,
        *,
        storage: RetentionStorage,
        semantic_index: EncryptedSemanticIndex,
        activity_store: EncryptedActivityStore,
        activity_rebuild: SurvivingRecordActivityReconciler,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._storage = storage
        self._semantic_index = semantic_index
        self._activity_store = activity_store
        self._activity_rebuild = activity_rebuild
        self._audit = audit

    def __repr__(self) -> str:
        return "GarbageCollector(dependencies=redacted)"

    async def collect(self) -> GarbageCollectionResult:
        await self._storage.recover()
        canonical = await self._canonical_ids()
        pruned = await self._prune_index(canonical)
        rebuilt = await self._rebuild_activity(canonical)
        self._emit(count=pruned, succeeded=True)
        return GarbageCollectionResult(
            pruned_index_entries=pruned,
            rebuilt_activity=rebuilt,
        )

    async def _canonical_ids(self) -> frozenset[UUID]:
        ids: set[UUID] = set()
        after_day = None
        after_id = None
        while True:
            page = await self._storage.page_ready(
                after_day=after_day,
                after_id=after_id,
                limit=10_000,
            )
            ids.update(entry.record_id for entry in page.entries)
            if page.complete:
                return frozenset(ids)
            last = page.entries[-1]
            after_day = last.day_bucket
            after_id = last.record_id

    async def _prune_index(self, canonical: frozenset[UUID]) -> int:
        indexed = await self._semantic_index.record_ids()
        stale = tuple(rid for rid in indexed if rid not in canonical)
        if not stale:
            return 0
        await self._semantic_index.remove(stale)
        return len(stale)

    async def _rebuild_activity(self, canonical: frozenset[UUID]) -> bool:
        snapshot = await self._activity_store.load()
        if snapshot is None:
            return False
        members = {
            record_id for entry in snapshot.entries for record_id in entry.cluster.source_record_ids
        }
        stale = tuple(members - canonical)
        if not stale:
            return False
        await self._activity_rebuild.reconcile_deleted(stale)
        return True

    def _emit(self, *, count: int, succeeded: bool) -> None:
        if self._audit is None:
            return
        self._audit.garbage_collection(count=count, succeeded=succeeded)
