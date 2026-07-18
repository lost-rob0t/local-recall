from __future__ import annotations

import asyncio
import os
import sqlite3
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid1, uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.ports.storage import DayRangeQuery, DeleteRequest
from local_recall.storage import (
    CURRENT_STORAGE_SCHEMA_VERSION,
    SQLiteEncryptedStorage,
    StorageFailure,
    StorageFailureCode,
    decode_envelope,
    encode_envelope,
)


def encrypted_envelope(
    *,
    record_id: UUID | None = None,
    created_at: datetime | None = None,
    ciphertext: bytes = b"synthetic-ciphertext",
) -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=record_id or uuid4(),
        generation=CaptureGeneration(3),
        configuration_revision="config-revision-fixture",
        schema_version=1,
        algorithm="xchacha20-poly1305-ietf",
        key=KeyHandle(key_id="fixture-key", provider_id="os-keyring", version=2),
        plaintext_frame_sizes=(128, 64),
        wrapped_data_key=b"w" * 48,
        nonce=b"n" * 24,
        ciphertext=ciphertext,
        associated_data_digest=b"d" * 32,
        created_at=created_at or datetime(2026, 7, 18, 12, 30, tzinfo=UTC),
    )


def backend(root: Path, **kwargs: object) -> SQLiteEncryptedStorage:
    return SQLiteEncryptedStorage(
        root,
        quota_bytes=cast(int, kwargs.pop("quota_bytes", 1_000_000)),
        max_blob_bytes=cast(int, kwargs.pop("max_blob_bytes", 100_000)),
        **cast(dict[str, object], kwargs),
    )


def test_persistent_envelope_round_trip() -> None:
    envelope = encrypted_envelope()
    encoded = encode_envelope(envelope)

    assert decode_envelope(encoded, max_blob_bytes=len(encoded)) == envelope


@pytest.mark.parametrize("mutation", ["truncate", "append", "magic", "length"])
def test_persistent_envelope_rejects_malformed_bytes(mutation: str) -> None:
    encoded = bytearray(encode_envelope(encrypted_envelope()))
    if mutation == "truncate":
        candidate = bytes(encoded[:-1])
    elif mutation == "append":
        candidate = bytes(encoded) + b"x"
    elif mutation == "magic":
        encoded[0] ^= 1
        candidate = bytes(encoded)
    else:
        encoded[10:14] = (2**31).to_bytes(4, "big")
        candidate = bytes(encoded)

    with pytest.raises(StorageFailure, match="storage_corruption"):
        decode_envelope(candidate, max_blob_bytes=max(len(candidate), 1024))


def test_persistent_envelope_rejects_time_ordered_record_identifier() -> None:
    envelope = replace(encrypted_envelope(), record_id=uuid1())

    with pytest.raises(StorageFailure) as captured:
        encode_envelope(envelope)

    assert captured.value.code is StorageFailureCode.INVALID_RECORD_ID


def test_round_trip_query_and_delete(tmp_path: Path) -> None:
    storage = backend(tmp_path)
    envelope = encrypted_envelope()

    stored = asyncio.run(storage.put(envelope))
    loaded = asyncio.run(storage.get(envelope.record_id))
    candidates = asyncio.run(
        storage.list_candidates(DayRangeQuery(date(2026, 7, 18), date(2026, 7, 18)))
    )
    deleted = asyncio.run(storage.delete(DeleteRequest(envelope.record_id, "user-request")))

    assert stored.record_id == envelope.record_id
    assert loaded == envelope
    assert tuple(candidate.record.record_id for candidate in candidates) == (envelope.record_id,)
    assert deleted.deleted
    assert not deleted.cryptographic_material_destroyed
    assert asyncio.run(storage.get(envelope.record_id)) is None


def test_storage_rejects_non_envelope_and_nonopaque_identifier(tmp_path: Path) -> None:
    storage = backend(tmp_path)

    with pytest.raises(StorageFailure) as raw_failure:
        asyncio.run(storage.put(cast(EncryptedRecordEnvelope, b"raw-frame")))
    with pytest.raises(StorageFailure) as identifier_failure:
        asyncio.run(storage.put(encrypted_envelope(record_id=uuid1())))

    assert raw_failure.value.code is StorageFailureCode.INVALID_TYPE
    assert identifier_failure.value.code is StorageFailureCode.INVALID_RECORD_ID


def test_quota_counts_existing_opaque_files(tmp_path: Path) -> None:
    storage = backend(tmp_path, quota_bytes=2_000, max_blob_bytes=1_500)
    asyncio.run(storage.put(encrypted_envelope(ciphertext=b"a" * 700)))

    with pytest.raises(StorageFailure) as captured:
        asyncio.run(storage.put(encrypted_envelope(ciphertext=b"b" * 700)))

    assert captured.value.code is StorageFailureCode.QUOTA_EXCEEDED


def test_interrupted_write_after_blob_rename_recovers(tmp_path: Path) -> None:
    def fault(point: str) -> None:
        if point == "after_blob_rename":
            raise RuntimeError("synthetic crash")

    envelope = encrypted_envelope()
    interrupted = backend(tmp_path, fault_injector=fault)
    with pytest.raises(StorageFailure):
        asyncio.run(interrupted.put(envelope))
    interrupted.close_sync()

    recovered = backend(tmp_path)

    assert asyncio.run(recovered.get(envelope.record_id)) == envelope


def test_interrupted_delete_is_completed_on_recovery(tmp_path: Path) -> None:
    armed = False

    def fault(point: str) -> None:
        if armed and point == "after_delete_mark":
            raise RuntimeError("synthetic crash")

    envelope = encrypted_envelope()
    interrupted = backend(tmp_path, fault_injector=fault)
    asyncio.run(interrupted.put(envelope))
    armed = True
    with pytest.raises(RuntimeError, match="synthetic crash"):
        asyncio.run(interrupted.delete(DeleteRequest(envelope.record_id, "user-request")))
    interrupted.close_sync()

    recovered = backend(tmp_path)

    assert asyncio.run(recovered.get(envelope.record_id)) is None


def test_corrupt_blob_is_quarantined_and_hidden(tmp_path: Path) -> None:
    storage = backend(tmp_path)
    envelope = encrypted_envelope()
    stored = asyncio.run(storage.put(envelope))
    path = storage.paths.blobs / stored.storage_id
    content = bytearray(path.read_bytes())
    content[-1] ^= 1
    path.write_bytes(content)

    with pytest.raises(StorageFailure) as captured:
        asyncio.run(storage.get(envelope.record_id))

    assert captured.value.code is StorageFailureCode.CORRUPTION
    assert list(storage.paths.quarantine.glob("*.lrq"))
    assert asyncio.run(storage.get(envelope.record_id)) is None


def test_storage_paths_and_files_are_owner_only(tmp_path: Path) -> None:
    storage = backend(tmp_path)
    stored = asyncio.run(storage.put(encrypted_envelope()))

    assert os.stat(storage.paths.root).st_mode & 0o777 == 0o700
    assert os.stat(storage.paths.catalog).st_mode & 0o777 == 0o600
    assert os.stat(storage.paths.blobs / stored.storage_id).st_mode & 0o777 == 0o600


def test_symlink_root_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(StorageFailure) as captured:
        backend(link)

    assert captured.value.code is StorageFailureCode.UNSAFE_ROOT


def test_v1_catalog_fixture_migrates_forward(tmp_path: Path) -> None:
    envelope = encrypted_envelope()
    blob = encode_envelope(envelope)
    token = f"{envelope.record_id.hex[:2]}/{envelope.record_id.hex}.lre"
    blob_path = tmp_path / "blobs" / token
    blob_path.parent.mkdir(parents=True)
    blob_path.write_bytes(blob)
    (tmp_path / "tmp").mkdir()
    (tmp_path / "quarantine").mkdir()

    with sqlite3.connect(tmp_path / "catalog.sqlite3") as catalog:
        catalog.executescript(
            """
            CREATE TABLE records (
                record_id TEXT PRIMARY KEY,
                envelope_schema_version INTEGER NOT NULL,
                key_provider_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                key_version INTEGER NOT NULL,
                ciphertext_bytes INTEGER NOT NULL,
                blob_bytes INTEGER NOT NULL,
                day_bucket TEXT NOT NULL,
                blob_token TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL
            );
            PRAGMA user_version = 1;
            """
        )
        catalog.execute(
            "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(envelope.record_id),
                envelope.schema_version,
                envelope.key.provider_id,
                envelope.key.key_id,
                envelope.key.version,
                len(envelope.ciphertext),
                len(blob),
                "2026-07-18",
                token,
                "ready",
            ),
        )

    storage = backend(tmp_path)

    assert asyncio.run(storage.get(envelope.record_id)) == envelope
    with sqlite3.connect(storage.paths.catalog) as migrated:
        assert migrated.execute("PRAGMA user_version").fetchone() == (
            CURRENT_STORAGE_SCHEMA_VERSION,
        )
        columns = {row[1] for row in migrated.execute("PRAGMA table_info(records)")}
    assert {"blob_digest", "migration_version", "artifact_kind"}.issubset(columns)
