# pyright: reportPrivateUsage=false, reportUnusedClass=false
from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, date
from typing import cast
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, StoredRecordRef
from local_recall.ports.storage import CatalogRecord, DayRangeQuery, DeleteRequest, DeleteResult

from .base import _SQLiteStorageBase
from .codec import decode_envelope, encode_envelope
from .errors import StorageFailure, StorageFailureCode
from .filesystem import (
    blob_path,
    blob_token,
    content_bytes_on_disk,
    ensure_catalog_permissions,
    fsync_directory,
    quarantine_path,
    read_blob,
    write_blob_atomically,
)
from .models import CatalogState
from .schema import CURRENT_STORAGE_SCHEMA_VERSION

_RECORD_INSERT = """
INSERT INTO records (
    record_id, artifact_kind, envelope_schema_version, key_provider_id,
    key_id, key_version, ciphertext_bytes, blob_bytes, day_bucket,
    blob_token, blob_digest, state, migration_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_INTENT_INSERT = """
INSERT INTO write_intents (
    record_id, artifact_kind, envelope_schema_version, key_provider_id,
    key_id, key_version, ciphertext_bytes, blob_bytes, day_bucket,
    blob_token, blob_digest
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class _SQLiteStorageOperations(_SQLiteStorageBase):
    def _put_sync(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        blob = encode_envelope(envelope)
        if len(blob) > self._max_blob_bytes:
            raise StorageFailure(StorageFailureCode.BLOB_TOO_LARGE, record_id=envelope.record_id)
        digest = hashlib.sha256(blob).digest()
        token = blob_token(envelope.record_id)
        metadata = self._metadata(envelope, blob, token, digest)
        with self._lock:
            existing = self._connection.execute(
                "SELECT blob_digest, envelope_schema_version FROM records WHERE record_id = ?",
                (str(envelope.record_id),),
            ).fetchone()
            if existing is not None:
                if cast(bytes, existing["blob_digest"]) == digest:
                    return StoredRecordRef(
                        envelope.record_id,
                        token,
                        cast(int, existing["envelope_schema_version"]),
                    )
                raise StorageFailure(
                    StorageFailureCode.DUPLICATE_RECORD, record_id=envelope.record_id
                )
            if content_bytes_on_disk(self._paths) + len(blob) > self._quota_bytes:
                raise StorageFailure(
                    StorageFailureCode.QUOTA_EXCEEDED, record_id=envelope.record_id
                )
            try:
                self._transaction(_INTENT_INSERT, metadata)
                self._fault("after_write_intent")
                write_blob_atomically(self._paths, token, blob, self._fault)
                self._fault("after_blob_rename")
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    _RECORD_INSERT,
                    (*metadata, CatalogState.READY.value, CURRENT_STORAGE_SCHEMA_VERSION),
                )
                self._connection.execute(
                    "DELETE FROM write_intents WHERE record_id = ?", (str(envelope.record_id),)
                )
                self._connection.execute("COMMIT")
                ensure_catalog_permissions(self._paths)
            except StorageFailure:
                self._rollback()
                raise
            except Exception as exc:
                self._rollback()
                raise StorageFailure(
                    StorageFailureCode.IO_FAILURE, record_id=envelope.record_id
                ) from exc
        return StoredRecordRef(envelope.record_id, token, envelope.schema_version)

    def _get_sync(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM records WHERE record_id = ? AND state = 'ready'",
                (str(record_id),),
            ).fetchone()
            if row is None:
                return None
            try:
                return self._decode_row(row)
            except (StorageFailure, OSError) as exc:
                self._quarantine_row(row)
                if isinstance(exc, StorageFailure):
                    raise
                raise StorageFailure(StorageFailureCode.CORRUPTION, record_id=record_id) from exc

    def _delete_sync(self, request: DeleteRequest) -> DeleteResult:
        with self._lock:
            row = self._connection.execute(
                "SELECT record_id, blob_token FROM records WHERE record_id = ?",
                (str(request.record_id),),
            ).fetchone()
            if row is None:
                return DeleteResult(request.record_id, False, False)
            self._transaction(
                "UPDATE records SET state = 'deleting' WHERE record_id = ?",
                (str(request.record_id),),
            )
            self._fault("after_delete_mark")
            path = blob_path(self._paths, cast(str, row["blob_token"]))
            try:
                path.unlink(missing_ok=True)
                fsync_directory(path.parent)
                self._transaction(
                    "DELETE FROM records WHERE record_id = ?", (str(request.record_id),)
                )
                ensure_catalog_permissions(self._paths)
            except OSError as exc:
                self._rollback()
                raise StorageFailure(
                    StorageFailureCode.IO_FAILURE, record_id=request.record_id
                ) from exc
            return DeleteResult(request.record_id, True, False)

    def _list_candidates_sync(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT record_id, envelope_schema_version, day_bucket, blob_bytes,
                       key_provider_id, key_id, key_version, blob_token
                FROM records
                WHERE state = 'ready' AND day_bucket BETWEEN ? AND ?
                ORDER BY day_bucket, record_id
                LIMIT ?
                """,
                (request.start_day.isoformat(), request.end_day.isoformat(), request.limit),
            ).fetchall()
        return tuple(
            CatalogRecord(
                StoredRecordRef(
                    UUID(cast(str, row["record_id"])),
                    cast(str, row["blob_token"]),
                    cast(int, row["envelope_schema_version"]),
                ),
                date.fromisoformat(cast(str, row["day_bucket"])),
                cast(int, row["blob_bytes"]),
                cast(str, row["key_provider_id"]),
                cast(str, row["key_id"]),
                cast(int, row["key_version"]),
            )
            for row in rows
        )

    def _decode_row(self, row: sqlite3.Row) -> EncryptedRecordEnvelope:
        blob = read_blob(self._paths, cast(str, row["blob_token"]), self._max_blob_bytes)
        if len(blob) != cast(int, row["blob_bytes"]) or hashlib.sha256(blob).digest() != cast(
            bytes, row["blob_digest"]
        ):
            raise StorageFailure(StorageFailureCode.CORRUPTION)
        envelope = decode_envelope(blob, max_blob_bytes=self._max_blob_bytes)
        if (
            self._metadata(
                envelope, blob, cast(str, row["blob_token"]), cast(bytes, row["blob_digest"])
            )
            != tuple(row)[:11]
        ):
            raise StorageFailure(StorageFailureCode.CORRUPTION, record_id=envelope.record_id)
        return envelope

    def _metadata(
        self,
        envelope: EncryptedRecordEnvelope,
        blob: bytes,
        token: str,
        digest: bytes,
    ) -> tuple[object, ...]:
        return (
            str(envelope.record_id),
            "capture-record",
            envelope.schema_version,
            envelope.key.provider_id,
            envelope.key.key_id,
            envelope.key.version,
            len(envelope.ciphertext),
            len(blob),
            envelope.created_at.astimezone(UTC).date().isoformat(),
            token,
            digest,
        )

    def _quarantine_row(self, row: sqlite3.Row) -> None:
        quarantine_path(self._paths, blob_path(self._paths, cast(str, row["blob_token"])))
        self._connection.execute(
            "UPDATE records SET state = 'quarantined' WHERE record_id = ?",
            (row["record_id"],),
        )
