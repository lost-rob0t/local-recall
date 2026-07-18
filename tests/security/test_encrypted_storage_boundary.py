from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.storage import SQLiteEncryptedStorage, StorageFailure, encode_envelope


def envelope() -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=uuid4(),
        generation=CaptureGeneration(1),
        configuration_revision="configuration-revision-seed",
        schema_version=1,
        algorithm="xchacha20-poly1305-ietf",
        key=KeyHandle("opaque-key", "os-keyring", 1),
        plaintext_frame_sizes=(64,),
        wrapped_data_key=b"w" * 48,
        nonce=b"n" * 24,
        ciphertext=b"opaque-encrypted-payload",
        associated_data_digest=b"d" * 32,
        created_at=datetime(2026, 7, 18, 14, 23, 45, tzinfo=UTC),
    )


def storage(root: Path) -> SQLiteEncryptedStorage:
    return SQLiteEncryptedStorage(root, quota_bytes=1_000_000, max_blob_bytes=100_000)


def test_filesystem_and_catalog_expose_no_captured_plaintext(tmp_path: Path) -> None:
    backend = storage(tmp_path)
    record = envelope()
    asyncio.run(backend.put(record))
    seeded_values = (
        b"synthetic-window-title-seed",
        b"synthetic-ocr-text-seed",
        b"https://synthetic.invalid/private",
        b"configuration-revision-seed",
        record.created_at.isoformat().encode(),
    )

    disk_bytes = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    with sqlite3.connect(backend.paths.catalog) as catalog:
        dump = "\n".join(catalog.iterdump()).encode()
        columns = {row[1] for row in catalog.execute("PRAGMA table_info(records)")}

    assert all(value not in disk_bytes for value in seeded_values[:3])
    assert all(value not in dump for value in seeded_values)
    assert {
        "created_at",
        "configuration_revision",
        "window_title",
        "url",
        "ocr_text",
        "prompt",
        "summary",
        "embedding",
    }.isdisjoint(columns)
    assert not list(tmp_path.rglob("*.png"))
    assert not list(tmp_path.rglob("*.jpg"))


def test_storage_runtime_rejects_raw_bytes_before_disk_write(tmp_path: Path) -> None:
    backend = storage(tmp_path)

    with pytest.raises(StorageFailure):
        asyncio.run(backend.put(cast(EncryptedRecordEnvelope, b"raw-pixels-and-text")))

    assert not list(backend.paths.blobs.rglob("*.lre"))


def test_orphan_files_are_reindexed_only_when_valid_envelopes(tmp_path: Path) -> None:
    backend = storage(tmp_path)
    record = envelope()
    encoded = encode_envelope(record)
    token = f"{record.record_id.hex[:2]}/{record.record_id.hex}.lre"
    orphan = backend.paths.blobs / token
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(encoded)

    report = asyncio.run(backend.recover())

    assert report.indexed_orphans == 1
    assert asyncio.run(backend.get(record.record_id)) == record
