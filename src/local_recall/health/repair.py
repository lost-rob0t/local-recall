"""Explicit, restartable, audited safe-repair operations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from local_recall.audit.recorder import AuditRecorder
from local_recall.health.ports import (
    IndexRepairPort,
    MigrationRepairPort,
    ProviderReprobePort,
    StorageRepairPort,
)


class RepairCommand(StrEnum):
    INDEX_REBUILD = "index-rebuild"
    ORPHAN_CLEANUP = "orphan-cleanup"
    MIGRATION_RESUME = "migration-resume"
    PROVIDER_REPROBE = "provider-reprobe"


class RepairStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True, repr=False)
class RepairRequest:
    command: RepairCommand
    requested_at: datetime
    reason_code: str

    def __post_init__(self) -> None:
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("repair request timestamp must be timezone-aware")
        if not self.reason_code:
            raise ValueError("repair reason code must not be empty")

    def __repr__(self) -> str:
        return (
            f"RepairRequest(command={self.command.value!r}, requested_at=<opaque>, reason=<opaque>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RepairOutcome:
    command: RepairCommand
    status: RepairStatus
    reason_code: str
    audit_event_id: UUID | None
    count: int
    restartable: bool

    def __repr__(self) -> str:
        return (
            f"RepairOutcome(command={self.command.value!r}, status={self.status.value!r}, "
            f"reason=<opaque>, count={self.count}, restartable={self.restartable})"
        )


class RepairLedger:
    """Restartable journal of repair outcomes, keyed by command."""

    def __init__(self) -> None:
        self._outcomes: dict[RepairCommand, RepairOutcome] = {}

    def record(self, outcome: RepairOutcome) -> None:
        self._outcomes[outcome.command] = outcome

    def resume_state(self, command: RepairCommand) -> RepairOutcome | None:
        return self._outcomes.get(command)


class SafeRepairService:
    """Run only explicitly requested, non-destructive repair operations."""

    def __init__(
        self,
        *,
        audit: AuditRecorder,
        now: Callable[[], datetime],
        index_repair: IndexRepairPort | None = None,
        storage_repair: StorageRepairPort | None = None,
        migration_repair: MigrationRepairPort | None = None,
        provider_reprobe: ProviderReprobePort | None = None,
        ledger: RepairLedger | None = None,
    ) -> None:
        del now
        self._audit = audit
        self._index_repair = index_repair
        self._storage_repair = storage_repair
        self._migration_repair = migration_repair
        self._provider_reprobe = provider_reprobe
        self._ledger = ledger or RepairLedger()

    @property
    def ledger(self) -> RepairLedger:
        return self._ledger

    async def run(self, request: RepairRequest) -> RepairOutcome:
        try:
            count = await self._execute(request.command)
        except _RepairUnavailable:
            return self._finalize(
                request.command,
                RepairStatus.UNAVAILABLE,
                "repair-port-unavailable",
                succeeded=False,
                count=0,
            )
        except Exception:
            return self._finalize(
                request.command,
                RepairStatus.FAILED,
                "repair-operation-failed",
                succeeded=False,
                count=0,
            )
        return self._finalize(
            request.command, RepairStatus.COMPLETED, "repair-completed", succeeded=True, count=count
        )

    async def _execute(self, command: RepairCommand) -> int:
        if command is RepairCommand.INDEX_REBUILD:
            if self._index_repair is None:
                raise _RepairUnavailable
            result = await self._index_repair.rebuild_index()
        elif command is RepairCommand.ORPHAN_CLEANUP:
            if self._storage_repair is None:
                raise _RepairUnavailable
            report = await self._storage_repair.cleanup_orphans()
            result = (
                report.recovered_writes
                + report.removed_temporary_files
                + report.completed_deletions
                + report.indexed_orphans
            )
        elif command is RepairCommand.MIGRATION_RESUME:
            if self._migration_repair is None:
                raise _RepairUnavailable
            result = await self._migration_repair.resume_migrations()
        else:
            if self._provider_reprobe is None:
                raise _RepairUnavailable
            result = await self._provider_reprobe.reprobe_providers()
        if result < 0:
            raise ValueError("repair result count is negative")
        return result

    def _finalize(
        self,
        command: RepairCommand,
        status: RepairStatus,
        reason_code: str,
        *,
        succeeded: bool,
        count: int,
    ) -> RepairOutcome:
        event = self._audit.record_repair_operation(
            command=command.value, succeeded=succeeded, restartable=True, count=count
        )
        outcome = RepairOutcome(
            command=command,
            status=status,
            reason_code=reason_code,
            audit_event_id=event.event_id,
            count=count,
            restartable=True,
        )
        self._ledger.record(outcome)
        return outcome


class _RepairUnavailable(Exception):
    pass
