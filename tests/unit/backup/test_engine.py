from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from local_recall.backup.engine import BackupEngine

from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.models import AuditAction
from local_recall.backup.archive import BackupArchive, RestoreFailure
from local_recall.crypto import OSKeyringProvider
from local_recall.domain.frames import RedactedRecord
from local_recall.storage import SQLiteEncryptedStorage
from tests.unit.retention.test_planner import make_envelope, make_record


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class _Decryptor:
    provider_id = "backup-decryptor"

    def __init__(self) -> None:
        self.decrypted: list[object] = []

    async def decrypt(self, request):
        self.decrypted.append(request.envelope.record_id)
        raise AssertionError("backup must never decrypt")

    async def encrypt(self, request):
        raise AssertionError("backup must never encrypt")


def _wire(tmp_path: Path, records: list[RedactedRecord]):
    source = SQLiteEncryptedStorage(
        tmp_path / "source", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    for record in records:
        asyncio.run(source.put(make_envelope(record)))
    sink = MemoryAuditSink()
    engine = BackupEngine(
        source_storage=source,
        audit=AuditRecorder(sink),
        key_provider=OSKeyringProvider(MemoryKeyringBackend()),
    )
    return engine, source, sink


def test_export_writes_sanitized_archive_and_restores_searchable_records(tmp_path: Path) -> None:
    first = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    second = make_record(2, captured_at=datetime(2026, 8, 2, 10, 0, tzinfo=UTC))
    engine, source, sink = _wire(tmp_path, [first, second])
    archive_path = tmp_path / "backup.lrb"

    export = asyncio.run(engine.export(archive_path))

    assert export.record_count == 2
    assert archive_path.exists()
    raw = archive_path.read_bytes()
    assert b"retention-entry" not in raw
    assert first.frame.captured_at.isoformat().encode() not in raw

    target = SQLiteEncryptedStorage(
        tmp_path / "target", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    restore = asyncio.run(engine.restore(archive_path, target))

    assert restore.restored_count == 2
    assert asyncio.run(target.get(first.record_id)) is not None
    assert asyncio.run(target.get(second.record_id)) is not None
    actions = {event.action for event in sink.events}
    assert AuditAction.EXPORT_DECISION in actions
    assert AuditAction.RESTORE_DECISION in actions


def test_archive_manifest_is_sanitized_and_typed(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    engine, source, sink = _wire(tmp_path, [record])
    archive_path = tmp_path / "backup.lrb"
    asyncio.run(engine.export(archive_path))

    parsed = BackupArchive.read(archive_path, max_blob_bytes=1_000_000)
    manifest = parsed.manifest

    assert manifest.format_version == 1
    assert manifest.schema_version >= 1
    assert manifest.record_count == 1
    encoded = json.dumps(manifest.to_dict())
    assert "emacs" not in encoded
    assert "retention-entry-1" not in encoded


def test_restore_into_non_empty_target_requires_explicit_flag(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    engine, source, sink = _wire(tmp_path, [record])
    archive_path = tmp_path / "backup.lrb"
    asyncio.run(engine.export(archive_path))
    target = SQLiteEncryptedStorage(
        tmp_path / "target", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    other = make_record(2, captured_at=datetime(2026, 8, 2, 10, 0, tzinfo=UTC))
    asyncio.run(target.put(make_envelope(other)))

    with pytest.raises(RestoreFailure, match="not empty"):
        asyncio.run(engine.restore(archive_path, target))

    forced = asyncio.run(engine.restore(archive_path, target, allow_non_empty=True))
    assert forced.restored_count == 1


def test_restore_detects_conflicting_duplicates_and_skips_identical(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    engine, source, sink = _wire(tmp_path, [record])
    archive_path = tmp_path / "backup.lrb"
    asyncio.run(engine.export(archive_path))
    target = SQLiteEncryptedStorage(
        tmp_path / "target", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    asyncio.run(target.put(make_envelope(record)))

    result = asyncio.run(engine.restore(archive_path, target, allow_non_empty=True))

    assert result.restored_count == 0
    assert result.skipped_duplicates == 1


def test_truncated_or_corrupted_archive_fails_safely(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    engine, source, sink = _wire(tmp_path, [record])
    archive_path = tmp_path / "backup.lrb"
    asyncio.run(engine.export(archive_path))
    target = SQLiteEncryptedStorage(
        tmp_path / "target", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )

    good = archive_path.read_bytes()
    archive_path.write_bytes(good[: len(good) // 2])
    with pytest.raises(RestoreFailure):
        asyncio.run(engine.restore(archive_path, target))

    corrupted = bytearray(good)
    corrupted[-10] ^= 0xFF
    archive_path.write_bytes(bytes(corrupted))
    with pytest.raises(RestoreFailure):
        asyncio.run(engine.restore(archive_path, target))
    assert asyncio.run(target.stats()).ready_records == 0


def test_export_by_time_range_only_includes_window(tmp_path: Path) -> None:
    old = make_record(1, captured_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC))
    new = make_record(2, captured_at=datetime(2026, 8, 2, 10, 0, tzinfo=UTC))
    engine, source, sink = _wire(tmp_path, [old, new])
    archive_path = tmp_path / "partial.lrb"

    export = asyncio.run(
        engine.export(
            archive_path,
            start=datetime(2026, 8, 1, 0, 0, tzinfo=UTC),
            end=datetime(2026, 8, 3, 0, 0, tzinfo=UTC),
        )
    )

    assert export.record_count == 1
    target = SQLiteEncryptedStorage(
        tmp_path / "target", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    asyncio.run(engine.restore(archive_path, target))
    assert asyncio.run(target.get(new.record_id)) is not None
    assert asyncio.run(target.get(old.record_id)) is None
