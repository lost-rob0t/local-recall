from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.ports.storage import DeleteRequest
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


def storage(root: Path, fault: Callable[[str], None] | None = None) -> SQLiteEncryptedStorage:
    return SQLiteEncryptedStorage(
        root,
        quota_bytes=1_000_000,
        max_blob_bytes=100_000,
        fault_injector=fault,
    )


def test_interrupted_write_after_blob_rename_recovers(tmp_path: Path) -> None:
    def fault(point: str) -> None:
        if point == "after_blob_rename":
            raise RuntimeError("synthetic crash")

    source = envelope()
    interrupted = storage(tmp_path, fault)
    with pytest.raises(StorageFailure):
        asyncio.run(interrupted.put(source))
    interrupted.close_sync()

    recovered = storage(tmp_path)
    assert asyncio.run(recovered.get(source.record_id)) == source


def test_interrupted_delete_is_completed_on_recovery(tmp_path: Path) -> None:
    armed = False

    def fault(point: str) -> None:
        if armed and point == "after_delete_mark":
            raise RuntimeError("synthetic crash")

    source = envelope()
    interrupted = storage(tmp_path, fault)
    asyncio.run(interrupted.put(source))
    armed = True
    with pytest.raises(RuntimeError, match="synthetic crash"):
        asyncio.run(interrupted.delete(DeleteRequest(source.record_id, "user-request")))
    interrupted.close_sync()

    recovered = storage(tmp_path)
    assert asyncio.run(recovered.get(source.record_id)) is None


def test_corrupt_blob_is_quarantined_and_hidden(tmp_path: Path) -> None:
    backend = storage(tmp_path)
    source = envelope()
    stored = asyncio.run(backend.put(source))
    path = backend.paths.blobs / stored.storage_id
    content = bytearray(path.read_bytes())
    content[-1] ^= 1
    path.write_bytes(content)

    with pytest.raises(StorageFailure) as captured:
        asyncio.run(backend.get(source.record_id))

    assert captured.value.code is StorageFailureCode.CORRUPTION
    assert list(backend.paths.quarantine.glob("*.lrq"))
    assert asyncio.run(backend.get(source.record_id)) is None
