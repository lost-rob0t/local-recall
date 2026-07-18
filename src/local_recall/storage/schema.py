from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC
from typing import cast
from uuid import UUID

from .codec import decode_envelope
from .errors import StorageFailure, StorageFailureCode
from .filesystem import StoragePaths, blob_token, read_blob

CURRENT_STORAGE_SCHEMA_VERSION = 2

CREATE_RECORDS_V2 = """
CREATE TABLE records (
    record_id TEXT PRIMARY KEY,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind = 'capture-record'),
    envelope_schema_version INTEGER NOT NULL CHECK (envelope_schema_version > 0),
    key_provider_id TEXT NOT NULL CHECK (length(key_provider_id) BETWEEN 1 AND 128),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 256),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    blob_bytes INTEGER NOT NULL CHECK (blob_bytes >= ciphertext_bytes),
    day_bucket TEXT NOT NULL CHECK (length(day_bucket) = 10),
    blob_token TEXT NOT NULL UNIQUE,
    blob_digest BLOB NOT NULL CHECK (length(blob_digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('ready', 'deleting', 'quarantined')),
    migration_version INTEGER NOT NULL CHECK (migration_version > 0)
)
"""
CREATE_DAY_INDEX = (
    "CREATE INDEX records_day_ready_idx ON records(day_bucket, record_id) WHERE state = 'ready'"
)
CREATE_WRITE_INTENTS_V2 = """
CREATE TABLE write_intents (
    record_id TEXT PRIMARY KEY,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind = 'capture-record'),
    envelope_schema_version INTEGER NOT NULL CHECK (envelope_schema_version > 0),
    key_provider_id TEXT NOT NULL CHECK (length(key_provider_id) BETWEEN 1 AND 128),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 256),
    key_version INTEGER NOT NULL CHECK (key_version > 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes > 0),
    blob_bytes INTEGER NOT NULL CHECK (blob_bytes >= ciphertext_bytes),
    day_bucket TEXT NOT NULL CHECK (length(day_bucket) = 10),
    blob_token TEXT NOT NULL UNIQUE,
    blob_digest BLOB NOT NULL CHECK (length(blob_digest) = 32)
)
"""

RECORDS_V2_COLUMNS = {
    "record_id",
    "artifact_kind",
    "envelope_schema_version",
    "key_provider_id",
    "key_id",
    "key_version",
    "ciphertext_bytes",
    "blob_bytes",
    "day_bucket",
    "blob_token",
    "blob_digest",
    "state",
    "migration_version",
}
WRITE_INTENTS_V2_COLUMNS = RECORDS_V2_COLUMNS - {"state", "migration_version"}
SCHEMA_V1_COLUMNS = {
    "record_id",
    "envelope_schema_version",
    "key_provider_id",
    "key_id",
    "key_version",
    "ciphertext_bytes",
    "blob_bytes",
    "day_bucket",
    "blob_token",
    "state",
}


def configure_connection(connection: sqlite3.Connection, busy_timeout_seconds: float) -> None:
    if busy_timeout_seconds <= 0:
        raise ValueError("busy_timeout_seconds must be positive")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute("PRAGMA secure_delete = ON")
    connection.execute("PRAGMA wal_autocheckpoint = 1000")
    connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_seconds * 1000)}")


def migrate_catalog(
    connection: sqlite3.Connection,
    paths: StoragePaths,
    max_blob_bytes: int,
) -> None:
    try:
        version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
    except (sqlite3.DatabaseError, TypeError, IndexError) as exc:
        raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE) from exc
    if version > CURRENT_STORAGE_SCHEMA_VERSION:
        raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
    if version == CURRENT_STORAGE_SCHEMA_VERSION:
        validate_current_schema(connection)
        return
    if version == 0:
        _create_fresh_catalog(connection)
        return
    if version == 1:
        migrate_v1_to_v2(connection, paths, max_blob_bytes)
        return
    raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)


def _create_fresh_catalog(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = _user_tables(connection)
        if existing:
            raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
        create_schema_v2(connection)
        connection.execute(f"PRAGMA user_version = {CURRENT_STORAGE_SCHEMA_VERSION}")
        connection.execute("COMMIT")
    except BaseException as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(exc, StorageFailure):
            raise
        raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE) from exc


def create_schema_v2(connection: sqlite3.Connection) -> None:
    connection.execute(CREATE_RECORDS_V2)
    connection.execute(CREATE_DAY_INDEX)
    connection.execute(CREATE_WRITE_INTENTS_V2)


def validate_current_schema(connection: sqlite3.Connection) -> None:
    try:
        tables = _user_tables(connection)
        if tables != {"records", "write_intents"}:
            raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
        records = {cast(str, row[1]) for row in connection.execute("PRAGMA table_info(records)")}
        intents = {
            cast(str, row[1]) for row in connection.execute("PRAGMA table_info(write_intents)")
        }
        if records != RECORDS_V2_COLUMNS or intents != WRITE_INTENTS_V2_COLUMNS:
            raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
        indexes = {cast(str, row[1]) for row in connection.execute("PRAGMA index_list(records)")}
        if "records_day_ready_idx" not in indexes:
            raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
    except sqlite3.DatabaseError as exc:
        raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE) from exc


def migrate_v1_to_v2(
    connection: sqlite3.Connection,
    paths: StoragePaths,
    max_blob_bytes: int,
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        if _user_tables(connection) != {"records"}:
            raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
        columns = {cast(str, row[1]) for row in connection.execute("PRAGMA table_info(records)")}
        if columns != SCHEMA_V1_COLUMNS:
            raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
        rows = connection.execute("SELECT * FROM records ORDER BY record_id").fetchall()
        connection.execute("DROP INDEX IF EXISTS records_day_ready_idx")
        connection.execute("ALTER TABLE records RENAME TO records_v1")
        create_schema_v2(connection)
        for row in rows:
            _migrate_v1_row(connection, row, paths, max_blob_bytes)
        connection.execute("DROP TABLE records_v1")
        connection.execute(f"PRAGMA user_version = {CURRENT_STORAGE_SCHEMA_VERSION}")
        connection.execute("COMMIT")
    except BaseException as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(exc, StorageFailure):
            raise
        raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE) from exc


def _migrate_v1_row(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    paths: StoragePaths,
    max_blob_bytes: int,
) -> None:
    token = cast(str, row["blob_token"])
    blob = read_blob(paths, token, max_blob_bytes)
    envelope = decode_envelope(blob, max_blob_bytes=max_blob_bytes)
    day_bucket = envelope.created_at.astimezone(UTC).date().isoformat()
    expected = (
        str(envelope.record_id),
        envelope.schema_version,
        envelope.key.provider_id,
        envelope.key.key_id,
        envelope.key.version,
        len(envelope.ciphertext),
        len(blob),
        day_bucket,
        blob_token(envelope.record_id),
    )
    actual = tuple(
        row[name]
        for name in (
            "record_id",
            "envelope_schema_version",
            "key_provider_id",
            "key_id",
            "key_version",
            "ciphertext_bytes",
            "blob_bytes",
            "day_bucket",
            "blob_token",
        )
    )
    try:
        UUID(cast(str, row["record_id"]))
    except (ValueError, TypeError):
        raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE) from None
    if actual != expected or row["state"] not in {"ready", "deleting", "quarantined"}:
        raise StorageFailure(StorageFailureCode.MIGRATION_FAILURE)
    connection.execute(
        """
        INSERT INTO records (
            record_id, artifact_kind, envelope_schema_version, key_provider_id,
            key_id, key_version, ciphertext_bytes, blob_bytes, day_bucket,
            blob_token, blob_digest, state, migration_version
        ) VALUES (?, 'capture-record', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row["record_id"],
            row["envelope_schema_version"],
            row["key_provider_id"],
            row["key_id"],
            row["key_version"],
            row["ciphertext_bytes"],
            row["blob_bytes"],
            row["day_bucket"],
            token,
            hashlib.sha256(blob).digest(),
            row["state"],
            CURRENT_STORAGE_SCHEMA_VERSION,
        ),
    )


def _user_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        cast(str, row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }
