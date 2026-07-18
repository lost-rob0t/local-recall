from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from local_recall.ports.storage import DeleteRequest
from local_recall.storage.errors import StorageFailure, StorageFailureCode
from local_recall.storage.filesystem import FilesystemStorageBackend
from local_recall.storage.models import StorageQuota, TimeRangeQuery
from tests.storage_helpers import MemoryKeyProvider, make_envelope


def test_filesystem_storage_round_trip_and_plaintext_inspection(tmp_path: Path) -> None:
    envelope = make_envelope()
    backend = FilesystemStorageBackend(
        tmp_path / "store",
        MemoryKeyProvider(),
        quota=StorageQuota(max_bytes=10_000_000, max_records=100),
    )

    stored = asyncio.run(backend.put(envelope))
    loaded = asyncio.run(backend.get(envelope.record_id))

    assert stored.record_id == envelope.record_id
    assert loaded == envelope
    persisted = b"".join(
        path.read_bytes() for path in (tmp_path / "store").rglob("*") if path.is_file()
    )
    assert envelope.configuration_revision.encode() not in persisted
    assert envelope.ciphertext not in persisted
    assert envelope.created_at.isoformat().encode() not in persisted


def test_interrupted_put_is_completed_by_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = make_envelope()
    provider = MemoryKeyProvider()
    backend = FilesystemStorageBackend(tmp_path / "store", provider)
    real_replace = os.replace
    failed = False

    def fail_first_blob_publish(
        source: str | bytes | Path,
        destination: str | bytes | Path,
    ) -> None:
        nonlocal failed
        if not failed and ".tmp-" in os.fsdecode(source):
            failed = True
            raise OSError("synthetic interruption")
        real_replace(source, destination)

    monkeypatch.setattr("local_recall.storage.filesystem.os.replace", fail_first_blob_publish)
    with pytest.raises(StorageFailure):
        asyncio.run(backend.put(envelope))

    monkeypatch.setattr("local_recall.storage.filesystem.os.replace", real_replace)
    reopened = FilesystemStorageBackend(tmp_path / "store", provider)

    assert asyncio.run(reopened.get(envelope.record_id)) == envelope


def test_time_range_query_supports_arbitrary_precise_intervals(tmp_path: Path) -> None:
    provider = MemoryKeyProvider()
    backend = FilesystemStorageBackend(tmp_path / "store", provider)
    eighteen_hours_ago = make_envelope(
        record_id=UUID("3b832319-4182-49dd-a3f3-fc73674ac829"),
        created_at=datetime(2026, 7, 17, 18, 0, 0, tzinfo=UTC),
    )
    six_minutes_ago = make_envelope(
        record_id=UUID("4de4d64d-556d-4184-b284-78afcd4f98e1"),
        created_at=datetime(2026, 7, 18, 11, 54, 0, tzinfo=UTC),
    )
    four_minutes_ago = make_envelope(
        record_id=UUID("a0a4abcf-c7f1-47d5-a6ea-a5993b609ffe"),
        created_at=datetime(2026, 7, 18, 11, 56, 0, tzinfo=UTC),
    )
    for envelope in (eighteen_hours_ago, six_minutes_ago, four_minutes_ago):
        asyncio.run(backend.put(envelope))

    five_minute_window = asyncio.run(
        backend.list_time_range(
            TimeRangeQuery(
                start_at=datetime(2026, 7, 18, 11, 55, 0, tzinfo=UTC),
                end_at=datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC),
                limit=10,
            )
        )
    )
    eighteen_hour_window = asyncio.run(
        backend.list_time_range(
            TimeRangeQuery(
                start_at=datetime(2026, 7, 17, 17, 59, 30, tzinfo=UTC),
                end_at=datetime(2026, 7, 17, 18, 0, 30, tzinfo=UTC),
                limit=10,
            )
        )
    )

    assert tuple(item.record_id for item in five_minute_window) == (four_minutes_ago.record_id,)
    assert five_minute_window[0].created_at == four_minutes_ago.created_at
    assert tuple(item.record_id for item in eighteen_hour_window) == (eighteen_hours_ago.record_id,)
    assert eighteen_hour_window[0].created_at == eighteen_hours_ago.created_at


def test_quota_rejection_is_fail_closed(tmp_path: Path) -> None:
    backend = FilesystemStorageBackend(
        tmp_path / "store",
        MemoryKeyProvider(),
        quota=StorageQuota(max_bytes=10_000_000, max_records=1),
    )
    first = make_envelope()
    second = make_envelope(record_id=UUID("a0a4abcf-c7f1-47d5-a6ea-a5993b609ffe"))
    asyncio.run(backend.put(first))

    with pytest.raises(StorageFailure) as exc_info:
        asyncio.run(backend.put(second))

    assert exc_info.value.code is StorageFailureCode.QUOTA_EXCEEDED
    assert asyncio.run(backend.get(second.record_id)) is None


def test_corruption_is_quarantined(tmp_path: Path) -> None:
    envelope = make_envelope()
    root = tmp_path / "store"
    backend = FilesystemStorageBackend(root, MemoryKeyProvider())
    asyncio.run(backend.put(envelope))
    blob = next((root / "blobs").rglob("*.lre"))
    blob.write_bytes(blob.read_bytes()[:-1] + b"X")

    with pytest.raises(StorageFailure) as exc_info:
        asyncio.run(backend.get(envelope.record_id))

    assert exc_info.value.code is StorageFailureCode.CORRUPT_RECORD
    assert not blob.exists()
    assert any((root / "quarantine").iterdir())


def test_delete_removes_record_without_claiming_secure_erase(tmp_path: Path) -> None:
    envelope = make_envelope()
    backend = FilesystemStorageBackend(tmp_path / "store", MemoryKeyProvider())
    asyncio.run(backend.put(envelope))

    result = asyncio.run(
        backend.delete(DeleteRequest(record_id=envelope.record_id, reason_code="test-delete"))
    )

    assert result.deleted
    assert not result.cryptographic_material_destroyed
    assert asyncio.run(backend.get(envelope.record_id)) is None
