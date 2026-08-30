"""Retention sweep execution with sanitized audit evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from local_recall.audit.recorder import AuditRecorder
from local_recall.ports.encryption import EncryptionProvider
from local_recall.ports.storage import DeleteRequest
from local_recall.retention.planner import RetentionPlanner, RetentionRules, RetentionStorage


@dataclass(frozen=True, slots=True)
class RetentionSweepResult:
    planned_count: int
    deleted_count: int
    reclaimed_bytes: int
    dry_run: bool


class RetentionEngine:
    """Apply the configured retention policy through canonical deletion.

    Every sweep plans first, then deletes each selected record through the
    idempotent canonical storage state machine. Dry runs never mutate
    storage. Sweeps are idempotent and safe to repeat after interruption;
    the sanitized audit event records only counts, reclaimed bytes, and the
    outcome.
    """

    def __init__(
        self,
        *,
        storage: RetentionStorage,
        encryption: EncryptionProvider | None,
        rules: RetentionRules,
        today: date,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._planner = RetentionPlanner(
            storage=storage,
            encryption=encryption,
            rules=rules,
            today=today,
        )
        self._storage = storage
        self._audit = audit

    def __repr__(self) -> str:
        return "RetentionEngine(rules=configured, dependencies=redacted)"

    async def sweep(self, *, dry_run: bool = False) -> RetentionSweepResult:
        plan = await self._planner.plan(dry_run=dry_run)
        selected = tuple(dict.fromkeys((*plan.expired, *plan.evicted)))
        if dry_run:
            self._emit(count=0, reclaimed=0, succeeded=True, dry_run=True)
            return RetentionSweepResult(
                planned_count=len(selected),
                deleted_count=0,
                reclaimed_bytes=0,
                dry_run=True,
            )
        deleted = 0
        for record_id in selected:
            result = await self._storage.delete(DeleteRequest(record_id, "retention-sweep"))
            if result.deleted:
                deleted += 1
        self._emit(count=deleted, reclaimed=plan.reclaimed_bytes, succeeded=True, dry_run=False)
        return RetentionSweepResult(
            planned_count=len(selected),
            deleted_count=deleted,
            reclaimed_bytes=plan.reclaimed_bytes,
            dry_run=False,
        )

    def _emit(self, *, count: int, reclaimed: int, succeeded: bool, dry_run: bool) -> None:
        if self._audit is not None:
            self._audit.retention_sweep(
                count=count,
                bytes_reclaimed=reclaimed,
                succeeded=succeeded,
                dry_run=dry_run,
            )
