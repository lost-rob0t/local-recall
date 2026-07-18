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
    persisted = b"".join(path.read_bytes() for path in (tmp_path / "store").rglob("*") if path.is_file())
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

    def fail_first_blob_publish(source: str | bytes | Path, destination: str | bytes | Path) -> None:
        nonlocal failed
        if not failed and ".tmp-" in os.fspath(source):
            failed = True
            raise OSError("synthetic interruption")
        real_replace(source, destination)

    monkeypatch.setattr("local_recall.storage.filesystem.os.replace", fail_first_blob_publish)
    with pytest.raises(StorageFailure):
        asyncio.run(backend.put(envelope))

    monkeypatch.setattr("local_recall.storage.filesystem.os.replace", real_replace)
    reopened = FilesystemStorageBackend(tmp_path / "store", provider)

    assert asyncio.run(reopened.get(envelope.record_id)) == envelope


def test_time_range_query_decrypts_only_coarse_day_candidates(tmp_path: Path) -> None:
    provider = MemoryKeyProvider()
    backend = FilesystemStorageBackend(tmp_path / "store", provider)
    first = make_envelope(created_at=datetime(2026, 7, 17, 23, 59, tzinfo=UTC))
    second = make_envelope(
        record_id=UUID("4de4d64d-556d-4184-b284-78afcd4f98e1"),
        created_at=datetime(2026, 7, 18, 0, 1, tzinfo=UTC),
    )
    asyncio.run(backend.put(first))
    asyncio.run(backend.put(second))

    matches = asyncio.run(
        backend.list_time_range(
            TimeRangeQuery(
                start_at=datetime(2026, 7, 18, tzinfo=UTC),
                end_at=datetime(2026, 7, 19, tzinfo=UTC),
                limit=10,
            )
        )
    )

    assert tuple(item.record_id for item in matches) == (second.record_id,)
    assert matches[0].created_at == second.created_at


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
