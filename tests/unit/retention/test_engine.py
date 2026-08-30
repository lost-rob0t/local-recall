from __future__ import annotations

import asyncio
import datetime as dt
from datetime import UTC, datetime
from pathlib import Path

import pytest

from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.models import AuditAction
from local_recall.domain.frames import RedactedRecord
from local_recall.retention.engine import RetentionEngine
from local_recall.retention.planner import RetentionRules
from local_recall.storage import SQLiteEncryptedStorage
from tests.unit.retention.test_planner import Decryptor, _envelope, _record


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _storage(tmp_path: Path, records: list[RedactedRecord]) -> SQLiteEncryptedStorage:
    storage = SQLiteEncryptedStorage(
        tmp_path / "storage", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    for record in records:
        asyncio.run(storage.put(_envelope(record)))
    return storage


def _engine(
    storage: SQLiteEncryptedStorage,
    records: list[RedactedRecord],
    rules: RetentionRules,
    *,
    audit: AuditRecorder | None = None,
) -> RetentionEngine:
    decryptor = Decryptor({r.record_id: r for r in records})
    return RetentionEngine(
        storage=storage,
        encryption=decryptor,
        rules=rules,
        today=dt.date(2026, 8, 30),
        audit=audit,
    )


def test_engine_applies_plan_and_deletes_expired_records(tmp_path: Path) -> None:
    expired = _record(1, captured_at=datetime(2026, 1, 5, 10, 0, tzinfo=UTC))
    fresh = _record(2, captured_at=datetime(2026, 8, 29, 10, 0, tzinfo=UTC))
    storage = _storage(tmp_path, [expired, fresh])
    sink = MemoryAuditSink()
    engine = _engine(
        storage,
        [expired, fresh],
        RetentionRules(max_age_days=30, max_bytes=1_000_000_000, max_records=250_000),
        audit=AuditRecorder(sink),
    )

    result = asyncio.run(engine.sweep())

    assert result.deleted_count == 1
    assert asyncio.run(storage.get(expired.record_id)) is None
    assert asyncio.run(storage.get(fresh.record_id)) is not None
    assert asyncio.run(storage.stats()).ready_records == 1
    sweeps = [e for e in sink.events if e.action is AuditAction.RETENTION_SWEEP]
    assert len(sweeps) == 1
    assert sweeps[0].attributes["count"] == 1
    assert sweeps[0].attributes["success"] is True
    assert "retention-entry-1" not in repr(sweeps[0])


def test_engine_dry_run_touches_nothing(tmp_path: Path) -> None:
    expired = _record(1, captured_at=datetime(2026, 1, 5, 10, 0, tzinfo=UTC))
    storage = _storage(tmp_path, [expired])
    engine = _engine(
        storage,
        [expired],
        RetentionRules(max_age_days=30, max_bytes=1_000_000_000, max_records=250_000),
    )

    result = asyncio.run(engine.sweep(dry_run=True))

    assert result.deleted_count == 0
    assert result.planned_count == 1
    assert asyncio.run(storage.get(expired.record_id)) is not None


def test_engine_is_idempotent_under_repeat_sweeps(tmp_path: Path) -> None:
    expired = _record(1, captured_at=datetime(2026, 1, 5, 10, 0, tzinfo=UTC))
    storage = _storage(tmp_path, [expired])
    engine = _engine(
        storage,
        [expired],
        RetentionRules(max_age_days=30, max_bytes=1_000_000_000, max_records=250_000),
    )

    first = asyncio.run(engine.sweep())
    second = asyncio.run(engine.sweep())

    assert first.deleted_count == 1
    assert second.deleted_count == 0


def test_engine_failure_audits_and_propagates(tmp_path: Path) -> None:
    from local_recall.audit.errors import AuditFailure, AuditFailureCode

    expired = _record(1, captured_at=datetime(2026, 1, 5, 10, 0, tzinfo=UTC))
    storage = _storage(tmp_path, [expired])

    class FailingSink:
        def emit(self, event: AuditEvent) -> None:
            raise AuditFailure(AuditFailureCode.IO_FAILURE)

    engine = RetentionEngine(
        storage=storage,
        encryption=Decryptor({r.record_id: r for r in [expired]}),
        rules=RetentionRules(max_age_days=30, max_bytes=1_000_000_000, max_records=250_000),
        today=dt.date(2026, 8, 30),
        audit=AuditRecorder(FailingSink()),
    )

    with pytest.raises(AuditFailure):
        asyncio.run(engine.sweep())
