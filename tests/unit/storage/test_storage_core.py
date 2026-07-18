from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.ports.storage import DayRangeQuery, DeleteRequest
from local_recall.storage import SQLiteEncryptedStorage, StorageFailure, StorageFailureCode


def envelope() -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=uuid4(),
        generation=CaptureGeneration(3),
        configuration_revision="fixture-revision",
        schema_version=1,
        algorithm="xchacha20-poly1305-ietf",
        key=KeyHandle("fixture-key", "os-keyring", 2),
        plaintext_frame_sizes=(128,),
        wrapped_data_key=b"w" * 48,
        nonce=b"n" * 24,
        ciphertext=b"synthetic-ciphertext",
        associated_data_digest=b"d" * 32,
        created_at=datetime(2026, 7, 18, 12, 30, tzinfo=UTC),
    )


def storage(root: Path) -> SQLiteEncryptedStorage:
    return SQLiteEncryptedStorage(root, quota_bytes=1_000_000, max_blob_bytes=100_000)


def test_round_trip_query_and_delete(tmp_path: Path) -> None:
    backend = storage(tmp_path)
    source = envelope()
    stored = asyncio.run(backend.put(source))

    assert asyncio.run(backend.get(source.record_id)) == source
    candidates = asyncio.run(
        backend.list_candidates(DayRangeQuery(date(2026, 7, 18), date(2026, 7, 18)))
    )
    assert tuple(item.record.record_id for item in candidates) == (source.record_id,)
    assert stored.record_id == source.record_id

    result = asyncio.run(backend.delete(DeleteRequest(source.record_id, "user-request")))
    assert result.deleted
    assert asyncio.run(backend.get(source.record_id)) is None


def test_storage_rejects_unencrypted_payload(tmp_path: Path) -> None:
    backend = storage(tmp_path)

    with pytest.raises(StorageFailure) as captured:
        asyncio.run(backend.put(cast(EncryptedRecordEnvelope, b"raw-frame")))

    assert captured.value.code is StorageFailureCode.INVALID_TYPE
