from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from ._catalog_schema import SELECT_COLUMNS, CatalogEntry, entry, initialize
from .errors import StorageFailure, StorageFailureCode
from .models import StorageQuota


class StorageCatalog:
    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path, timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode = DELETE")
        self.connection.execute("PRAGMA synchronous = FULL")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA temp_store = MEMORY")
        self.connection.execute("PRAGMA trusted_schema = OFF")
        initialize(self.connection)

    def close(self) -> None:
        self.connection.close()

    def select(self, record_id: UUID) -> CatalogEntry | None:
        try:
            row = self.connection.execute(
                f"SELECT {SELECT_COLUMNS} FROM records WHERE record_id = ?",
                (str(record_id),),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc
        return None if row is None else entry(row)

    def pending(self) -> tuple[CatalogEntry, ...]:
        try:
            rows = self.connection.execute(
                f"SELECT {SELECT_COLUMNS} FROM records "
                "WHERE state = 'pending' ORDER BY record_id"
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc
        return tuple(entry(row) for row in rows)

    def candidate_ids(self, start_bucket: str, end_bucket: str) -> tuple[UUID, ...]:
        try:
            rows = self.connection.execute(
                "SELECT record_id FROM records WHERE state = 'committed' "
                "AND day_bucket >= ? AND day_bucket <= ? "
                "ORDER BY day_bucket, record_id",
                (start_bucket, end_bucket),
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc
        return tuple(UUID(cast(str, row[0])) for row in rows)

    def check_quota(self, quota: StorageQuota, additional_bytes: int) -> None:
        try:
            row = self.connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(ciphertext_bytes), 0) "
                "FROM records WHERE state IN ('pending', 'committed', 'quarantined')"
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc
        values = (0, 0) if row is None else cast(tuple[Any, ...], tuple(row))
        if int(values[0]) + 1 > quota.max_records:
            raise StorageFailure(None, StorageFailureCode.QUOTA_EXCEEDED)
        if int(values[1]) + additional_bytes > quota.max_bytes:
            raise StorageFailure(None, StorageFailureCode.QUOTA_EXCEEDED)

    def insert_pending(
        self,
        *,
        record_id: UUID,
        storage_schema_version: int,
        envelope_schema_version: int,
        key_id: str,
        ciphertext_bytes: int,
        day_bucket: str,
        blob_token: str,
        temp_token: str,
        blob_digest: bytes,
    ) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO records (record_id, storage_schema_version, "
                    "envelope_schema_version, key_id, ciphertext_bytes, day_bucket, "
                    "blob_token, temp_token, blob_digest, state, migration_version) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0)",
                    (
                        str(record_id),
                        storage_schema_version,
                        envelope_schema_version,
                        key_id,
                        ciphertext_bytes,
                        day_bucket,
                        blob_token,
                        temp_token,
                        blob_digest,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise StorageFailure(record_id, StorageFailureCode.RECORD_CONFLICT) from exc
        except sqlite3.Error as exc:
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc

    def begin_replacement(
        self,
        current: CatalogEntry,
        *,
        storage_schema_version: int,
        envelope_schema_version: int,
        key_id: str,
        ciphertext_bytes: int,
        temp_token: str,
        blob_digest: bytes,
    ) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "UPDATE records SET storage_schema_version = ?, "
                    "envelope_schema_version = ?, key_id = ?, ciphertext_bytes = ?, "
                    "temp_token = ?, blob_digest = ?, state = 'pending', "
                    "migration_version = migration_version + 1 WHERE record_id = ?",
                    (
                        storage_schema_version,
                        envelope_schema_version,
                        key_id,
                        ciphertext_bytes,
                        temp_token,
                        blob_digest,
                        str(current.record_id),
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageFailure(
                current.record_id, StorageFailureCode.CATALOG_FAILURE
            ) from exc

    def mark_committed(self, record_id: UUID) -> None:
        self._update(
            record_id,
            "UPDATE records SET state = 'committed', temp_token = NULL "
            "WHERE record_id = ?",
        )

    def mark_quarantined(self, record_id: UUID, token: str) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "UPDATE records SET state = 'quarantined', blob_token = ?, "
                    "temp_token = NULL WHERE record_id = ?",
                    (token, str(record_id)),
                )
        except sqlite3.Error as exc:
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc

    def delete(self, record_id: UUID) -> None:
        self._update(record_id, "DELETE FROM records WHERE record_id = ?")

    def _update(self, record_id: UUID, statement: str) -> None:
        try:
            with self.connection:
                self.connection.execute(statement, (str(record_id),))
        except sqlite3.Error as exc:
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc
