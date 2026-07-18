from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.storage import CURRENT_STORAGE_SCHEMA_VERSION, SQLiteEncryptedStorage, encode_envelope


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


def test_v1_catalog_fixture_migrates_forward(tmp_path: Path) -> None:
    source = envelope()
    blob = encode_envelope(source)
    token = f"{source.record_id.hex[:2]}/{source.record_id.hex}.lre"
    path = tmp_path / "blobs" / token
    path.parent.mkdir(parents=True)
    path.write_bytes(blob)
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
                str(source.record_id),
                source.schema_version,
                source.key.provider_id,
                source.key.key_id,
                source.key.version,
                len(source.ciphertext),
                len(blob),
                "2026-07-18",
                token,
                "ready",
            ),
        )

    backend = SQLiteEncryptedStorage(tmp_path, quota_bytes=1_000_000, max_blob_bytes=100_000)

    assert asyncio.run(backend.get(source.record_id)) == source
    with sqlite3.connect(backend.paths.catalog) as migrated:
        assert migrated.execute("PRAGMA user_version").fetchone() == (
            CURRENT_STORAGE_SCHEMA_VERSION,
        )
        columns = {row[1] for row in migrated.execute("PRAGMA table_info(records)")}
    assert {"blob_digest", "migration_version", "artifact_kind"}.issubset(columns)
