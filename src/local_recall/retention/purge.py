"""Manual purge-all with cryptographic key destruction and sanitized audit."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from uuid import UUID

from local_recall.activity.store import ActivitySnapshot, EncryptedActivityStore
from local_recall.audit.recorder import AuditRecorder
from local_recall.crypto.errors import KeyProviderFailure, KeyProviderFailureCode
from local_recall.domain import KeyPurpose, KeyRequest
from local_recall.index.semantic import EncryptedSemanticIndex
from local_recall.ports.keys import KeyDestructionRequest, KeyProvider
from local_recall.ports.storage import DeleteRequest
from local_recall.retention.planner import RetentionStorage


@dataclass(frozen=True, slots=True)
class PurgeAllResult:
    planned_count: int
    deleted_count: int
    key_destroyed: bool
    dry_run: bool


class PurgeAllEngine:
    """Owner-invoked purge of every capture record using explicit canonical deletes.

    The purge deletes every ready record through the canonical storage state
    machine, replaces the encrypted activity snapshot with an empty one,
    clears the encrypted semantic index, and finally destroys the active
    record key so no capture record remains decryptable with the active key
    material. Dry runs plan and report without touching anything.
    """

    def __init__(
        self,
        *,
        storage: RetentionStorage,
        activity_store: EncryptedActivityStore,
        semantic_index: EncryptedSemanticIndex,
        key_provider: KeyProvider,
        audit: AuditRecorder | None = None,
        today: date | None = None,
    ) -> None:
        self._storage = storage
        self._activity_store = activity_store
        self._semantic_index = semantic_index
        self._key_provider = key_provider
        self._audit = audit
        self._today = today

    def __repr__(self) -> str:
        return "PurgeAllEngine(dependencies=redacted)"

    @property
    def key_provider(self) -> KeyProvider:
        return self._key_provider

    async def active_record_key(self):
        return await self._key_provider.active_key(
            KeyRequest(KeyPurpose.RECORD, create_if_missing=True)
        )

    async def purge(self, *, dry_run: bool = False) -> PurgeAllResult:
        planned = await self._all_record_ids()
        if dry_run:
            return PurgeAllResult(
                planned_count=len(planned),
                deleted_count=0,
                key_destroyed=False,
                dry_run=True,
            )
        deleted = 0
        for record_id in planned:
            result = await self._storage.delete(DeleteRequest(record_id, "purge-all"))
            if result.deleted:
                deleted += 1
        await self._semantic_index.clear()
        await self._activity_store.replace(ActivitySnapshot(entries=()))
        key_destroyed = await self._destroy_active_key()
        self._emit(count=deleted, key_destroyed=key_destroyed, succeeded=True)
        return PurgeAllResult(
            planned_count=len(planned),
            deleted_count=deleted,
            key_destroyed=key_destroyed,
            dry_run=False,
        )

    async def _all_record_ids(self) -> tuple[UUID, ...]:
        ids: list[UUID] = []
        after_day: date | None = None
        after_id: UUID | None = None
        while True:
            page = await self._storage.page_ready(
                after_day=after_day,
                after_id=after_id,
                limit=10_000,
            )
            ids.extend(entry.record_id for entry in page.entries)
            if page.complete:
                return tuple(ids)
            last = page.entries[-1]
            after_day = last.day_bucket
            after_id = last.record_id

    async def _destroy_active_key(self) -> bool:
        try:
            handle = await self._key_provider.active_key(KeyRequest(KeyPurpose.RECORD))
        except KeyProviderFailure as exc:
            if exc.code is KeyProviderFailureCode.KEY_NOT_FOUND:
                return False
            raise
        result = await self._key_provider.destroy(KeyDestructionRequest(handle, "purge-all"))
        return result.destroyed

    def _emit(self, *, count: int, key_destroyed: bool, succeeded: bool) -> None:
        if self._audit is None:
            return
        self._audit.purge_all(
            count=count,
            key_destroyed=key_destroyed,
            succeeded=succeeded,
        )
