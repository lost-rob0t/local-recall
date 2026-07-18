from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import cast
from uuid import UUID

from .errors import StorageFailure, StorageFailureCode

CATALOG_SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS records (
    record_id TEXT PRIMARY KEY,
    storage_schema_version INTEGER NOT NULL,
    envelope_schema_version INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    day_bucket TEXT NOT NULL CHECK (length(day_bucket) = 10),
    blob_token TEXT NOT NULL UNIQUE,
    temp_token TEXT,
    blob_digest BLOB NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'committed', 'quarantined')
    ),
    migration_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS records_day_state
ON records(day_bucket, state);
"""

SELECT_COLUMNS = """
record_id, storage_schema_version, envelope_schema_version,
key_id, ciphertext_bytes, day_bucket, blob_token,
temp_token, blob_digest, state
"""


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    record_id: UUID
    storage_schema_version: int
    envelope_schema_version: int
    key_id: str
    ciphertext_bytes: int
    day_bucket: str
    blob_token: str
    temp_token: str | None
    blob_digest: bytes
    state: str


def initialize(connection: sqlite3.Connection) -> None:
    try:
        with connection:
            connection.executescript(SCHEMA_SQL)
            version_row = connection.execute("PRAGMA user_version").fetchone()
            version = 0 if version_row is None else int(version_row[0])
            if version > CATALOG_SCHEMA_VERSION:
                raise StorageFailure(None, StorageFailureCode.UNSUPPORTED_SCHEMA)
            connection.execute(f"PRAGMA user_version = {CATALOG_SCHEMA_VERSION}")
    except sqlite3.Error as exc:
        raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc


def entry(row: sqlite3.Row) -> CatalogEntry:
    return CatalogEntry(
        record_id=UUID(cast(str, row["record_id"])),
        storage_schema_version=cast(int, row["storage_schema_version"]),
        envelope_schema_version=cast(int, row["envelope_schema_version"]),
        key_id=cast(str, row["key_id"]),
        ciphertext_bytes=cast(int, row["ciphertext_bytes"]),
        day_bucket=cast(str, row["day_bucket"]),
        blob_token=cast(str, row["blob_token"]),
        temp_token=cast(str | None, row["temp_token"]),
        blob_digest=cast(bytes, row["blob_digest"]),
        state=cast(str, row["state"]),
    )
