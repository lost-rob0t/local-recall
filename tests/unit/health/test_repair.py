from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from local_recall.audit import AuditRecorder
from local_recall.health.repair import (
    RepairCommand,
    RepairRequest,
    RepairStatus,
    SafeRepairService,
)
from local_recall.ports.storage import StorageIntegrityReport

_NOW = datetime(2026, 8, 30, tzinfo=UTC)


class CountingIndexRepair:
    def __init__(self, count: int) -> None:
        self._count = count
        self.calls = 0

    async def rebuild_index(self) -> int:
        self.calls += 1
        return self._count


class FlakyIndexRepair:
    def __init__(self) -> None:
        self.calls = 0

    async def rebuild_index(self) -> int:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("synthetic-sensitive-repair-marker")
        return 5


class RecordingStorageRepair:
    async def cleanup_orphans(self) -> StorageIntegrityReport:
        return StorageIntegrityReport(
            verified_records=4,
            recovered_writes=1,
            removed_temporary_files=2,
            completed_deletions=0,
            quarantined_records=0,
            indexed_orphans=3,
        )


class RecordingMigrationRepair:
    def __init__(self) -> None:
        self.calls = 0

    async def resume_migrations(self) -> int:
        self.calls += 1
        return 2


class RecordingProviderReprobe:
    def __init__(self) -> None:
        self.calls = 0

    async def reprobe_providers(self) -> int:
        self.calls += 1
        return 1


class SpyStorage:
    def __init__(self) -> None:
        self.delete_calls: list[object] = []

    async def cleanup_orphans(self) -> StorageIntegrityReport:
        return StorageIntegrityReport()

    async def delete(self, request: object) -> object:
        self.delete_calls.append(request)
        raise AssertionError("repair must never delete records")


@dataclass
class MemoryAuditSink:
    events: list[object] = field(default_factory=list[object])

    def emit(self, event: object) -> None:
        self.events.append(event)


def _request(command: RepairCommand) -> RepairRequest:
    return RepairRequest(command=command, requested_at=_NOW, reason_code="operator-request")


def _service(
    *,
    index_repair: object | None = None,
    storage_repair: object | None = None,
    migration_repair: object | None = None,
    provider_reprobe: object | None = None,
) -> tuple[SafeRepairService, MemoryAuditSink]:
    sink = MemoryAuditSink()
    service = SafeRepairService(
        index_repair=index_repair,
        storage_repair=storage_repair,
        migration_repair=migration_repair,
        provider_reprobe=provider_reprobe,
        audit=AuditRecorder(sink),
        now=lambda: _NOW,
    )
    return service, sink


def test_index_rebuild_is_completed_and_audited() -> None:
    service, sink = _service(index_repair=CountingIndexRepair(4))
    outcome = asyncio.run(service.run(_request(RepairCommand.INDEX_REBUILD)))
    assert outcome.status is RepairStatus.COMPLETED
    assert outcome.count == 4
    assert outcome.restartable is True
    assert outcome.audit_event_id is not None
    assert len(sink.events) == 1


def test_failed_repair_is_sanitized_and_restartable() -> None:
    service, sink = _service(index_repair=FlakyIndexRepair())
    first = asyncio.run(service.run(_request(RepairCommand.INDEX_REBUILD)))
    assert first.status is RepairStatus.FAILED
    assert first.reason_code == "repair-operation-failed"
    assert "synthetic-sensitive-repair-marker" not in repr(first)
    second = asyncio.run(service.run(_request(RepairCommand.INDEX_REBUILD)))
    assert second.status is RepairStatus.COMPLETED
    assert second.count == 5
    assert len(sink.events) == 2


def test_orphan_cleanup_reports_counts_and_audits() -> None:
    service, sink = _service(storage_repair=RecordingStorageRepair())
    outcome = asyncio.run(service.run(_request(RepairCommand.ORPHAN_CLEANUP)))
    assert outcome.status is RepairStatus.COMPLETED
    assert outcome.count == 6
    assert len(sink.events) == 1


def test_migration_resume_and_provider_reprobe() -> None:
    service, sink = _service(
        migration_repair=RecordingMigrationRepair(), provider_reprobe=RecordingProviderReprobe()
    )
    migrations = asyncio.run(service.run(_request(RepairCommand.MIGRATION_RESUME)))
    reprobes = asyncio.run(service.run(_request(RepairCommand.PROVIDER_REPROBE)))
    assert migrations.status is RepairStatus.COMPLETED
    assert migrations.count == 2
    assert reprobes.status is RepairStatus.COMPLETED
    assert reprobes.count == 1
    assert len(sink.events) == 2


def test_unconfigured_repair_is_unavailable() -> None:
    service, sink = _service()
    outcome = asyncio.run(service.run(_request(RepairCommand.INDEX_REBUILD)))
    assert outcome.status is RepairStatus.UNAVAILABLE
    assert outcome.reason_code == "repair-port-unavailable"
    assert len(sink.events) == 1


def test_repair_never_invokes_storage_delete() -> None:
    spy = SpyStorage()
    service, _sink = _service(storage_repair=spy)
    asyncio.run(service.run(_request(RepairCommand.ORPHAN_CLEANUP)))
    assert spy.delete_calls == []


def test_empty_reason_code_is_rejected() -> None:
    with pytest.raises(ValueError):
        RepairRequest(command=RepairCommand.INDEX_REBUILD, requested_at=_NOW, reason_code="")


def test_repair_commands_are_a_closed_set() -> None:
    assert {item.value for item in RepairCommand} == {
        "index-rebuild",
        "orphan-cleanup",
        "migration-resume",
        "provider-reprobe",
    }
