from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import sqlite3
import stat
import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager
from datetime import UTC, date
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, StoredRecordRef
from local_recall.ports.storage import DeleteRequest, DeleteResult

from .codec import decode_envelope, encode_envelope
from .errors import StorageFailure, StorageFailureCode
from .filesystem import (
    StoragePaths,
    blob_path,
    blob_token,
    content_bytes_on_disk,
    ensure_catalog_permissions,
    fsync_directory,
    iter_blob_files,
    prepare_paths,
    quarantine_path,
    read_blob,
    safe_unlink,
    write_blob_atomically,
)
from .models import CatalogRecord, DayRangeQuery, RecoveryReport
from .schema import (
    CURRENT_STORAGE_SCHEMA_VERSION,
    configure_connection,
    migrate_catalog,
    validate_current_schema,
)

if TYPE_CHECKING:
    from local_recall.config.models import StorageSettings

FaultInjector = Callable[[str], None]


def _no_fault(_: str) -> None:
    return None


class SQLiteBlobStorage:
    backend_id = "sqlite-blob"

    def __init__(
        self,
        root: Path,
        *,
        max_blob_bytes: int = 512 * 1024 * 1024,
        max_total_bytes: int = 32 * 1024 * 1024 * 1024,
        busy_timeout_seconds: float = 5.0,
        fault_injector: FaultInjector | None = None,
        recover_on_open: bool = True,
    ) -> None:
        if max_blob_bytes <= 0:
            raise ValueError("max_blob_bytes must be positive")
        if max_total_bytes < max_blob_bytes:
            raise ValueError("max_total_bytes must be at least max_blob_bytes")
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")
        self._max_blob_bytes = max_blob_bytes
        self._max_total_bytes = max_total_bytes
        self._busy_timeout_seconds = busy_timeout_seconds
        self._fault = fault_injector or _no_fault
        self._lock = threading.RLock()
        self._closed = False
        self._paths = prepare_paths(root)
        try:
            self._connection = sqlite3.connect(
                self._paths.catalog,
                timeout=busy_timeout_seconds,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            configure_connection(self._connection, busy_timeout_seconds)
            migrate_catalog(self._connection, self._paths, max_blob_bytes)
            ensure_catalog_permissions(self._paths)
            self._quick_check_locked()
            if recover_on_open:
                self._recover_locked()
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise

    @classmethod
    def from_settings(
        cls,
        settings: StorageSettings,
        *,
        fault_injector: FaultInjector | None = None,
        recover_on_open: bool = True,
    ) -> SQLiteBlobStorage:
        if settings.backend_id != cls.backend_id or settings.root_directory is None:
            raise StorageFailure(StorageFailureCode.INVALID_CONFIGURATION)
        return cls(
            Path(settings.root_directory),
            max_blob_bytes=settings.max_blob_bytes,
            max_total_bytes=settings.max_total_bytes,
            busy_timeout_seconds=settings.busy_timeout_seconds,
            fault_injector=fault_injector,
            recover_on_open=recover_on_open,
        )

    @property
    def paths(self) -> StoragePaths:
        return self._paths

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        return await asyncio.to_thread(self._put, envelope)

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        return await asyncio.to_thread(self._get, record_id)

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        return await asyncio.to_thread(self._delete, request)

    async def query_day_range(self, query: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        return await asyncio.to_thread(self._query_day_range, query)

    async def recover(self) -> RecoveryReport:
        return await asyncio.to_thread(self._recover)

    async def health_check(self) -> bool:
        return await asyncio.to_thread(self._health_check)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> SQLiteBlobStorage:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()

    def _put(self, envelope_value: object) -> StoredRecordRef:
        envelope = self._require_envelope(envelope_value)
        self._validate_record_id(envelope.record_id)
        blob = encode_envelope(envelope)
        if len(blob) > self._max_blob_bytes:
            raise StorageFailure(StorageFailureCode.BLOB_TOO_LARGE, record_id=envelope.record_id)
        digest = hashlib.sha256(blob).digest()
        token = blob_token(envelope.record_id)
        day_bucket = envelope.created_at.astimezone(UTC).date().isoformat()
        values = (
            str(envelope.record_id),
            "capture-record",
            envelope.schema_version,
            envelope.key.provider_id,
            envelope.key.key_id,
            envelope.key.version,
            len(envelope.ciphertext),
            len(blob),
            day_bucket,
            token,
            digest,
        )
        with self._lock:
            self._require_open_locked()
            if self._record_or_intent_exists_locked(envelope.record_id):
                raise StorageFailure(
                    StorageFailureCode.DUPLICATE_RECORD, record_id=envelope.record_id
                )
            used = content_bytes_on_disk(self._paths)
            if used + len(blob) > self._max_total_bytes:
                raise StorageFailure(
                    StorageFailureCode.QUOTA_EXCEEDED, record_id=envelope.record_id
                )
            with self._transaction_locked():
                self._connection.execute(
                    """
                    INSERT INTO write_intents (
                        record_id, artifact_kind, envelope_schema_version, key_provider_id,
                        key_id, key_version, ciphertext_bytes, blob_bytes, day_bucket,
                        blob_token, blob_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
            self._fault("after_intent_commit")
            write_blob_atomically(self._paths, token, blob, self._fault)
            self._fault("after_blob_rename")
            with self._transaction_locked():
                row = self._connection.execute(
                    "SELECT * FROM write_intents WHERE record_id = ?", (str(envelope.record_id),)
                ).fetchone()
                if row is None or not self._intent_matches_values(row, values):
                    raise StorageFailure(
                        StorageFailureCode.CATALOG_FAILURE, record_id=envelope.record_id
                    )
                self._connection.execute(
                    """
                    INSERT INTO records (
                        record_id, artifact_kind, envelope_schema_version, key_provider_id,
                        key_id, key_version, ciphertext_bytes, blob_bytes, day_bucket,
                        blob_token, blob_digest, state, migration_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)
                    """,
                    (*values, CURRENT_STORAGE_SCHEMA_VERSION),
                )
                self._connection.execute(
                    "DELETE FROM write_intents WHERE record_id = ?", (str(envelope.record_id),)
                )
                self._fault("before_catalog_commit")
            self._fault("after_catalog_commit")
            ensure_catalog_permissions(self._paths)
        return StoredRecordRef(
            record_id=envelope.record_id,
            storage_id=f"record:{envelope.record_id}",
            envelope_schema_version=envelope.schema_version,
        )

    def _get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        self._validate_record_id(record_id)
        with self._lock:
            self._require_open_locked()
            row = self._connection.execute(
                "SELECT * FROM records WHERE record_id = ?", (str(record_id),)
            ).fetchone()
            if row is None:
                return None
            if row["state"] != "ready":
                raise StorageFailure(StorageFailureCode.CORRUPTION, record_id=record_id)
            try:
                return self._load_row_locked(row)
            except StorageFailure:
                self._quarantine_record_locked(row)
                raise

    def _delete(self, request_value: object) -> DeleteResult:
        request = self._require_delete_request(request_value)
        self._validate_record_id(request.record_id)
        if not request.reason_code:
            raise ValueError("delete reason_code must not be empty")
        with self._lock:
            self._require_open_locked()
            row = self._connection.execute(
                "SELECT * FROM records WHERE record_id = ?", (str(request.record_id),)
            ).fetchone()
            if row is None:
                return DeleteResult(request.record_id, False, False)
            with self._transaction_locked():
                self._connection.execute(
                    "UPDATE records SET state = 'deleting' WHERE record_id = ?",
                    (str(request.record_id),),
                )
            self._fault("after_delete_mark")
            path = blob_path(self._paths, cast(str, row["blob_token"]))
            safe_unlink(path)
            if path.parent.exists():
                fsync_directory(path.parent)
            self._fault("after_blob_delete")
            with self._transaction_locked():
                self._connection.execute(
                    "DELETE FROM records WHERE record_id = ?", (str(request.record_id),)
                )
            self._fault("after_delete_commit")
            return DeleteResult(request.record_id, True, False)

    def _query_day_range(self, query_value: object) -> tuple[CatalogRecord, ...]:
        query = self._require_day_query(query_value)
        with self._lock:
            self._require_open_locked()
            rows = self._connection.execute(
                """
                SELECT record_id, day_bucket, envelope_schema_version, key_provider_id,
                       key_id, key_version, ciphertext_bytes, blob_bytes
                FROM records
                WHERE state = 'ready' AND day_bucket BETWEEN ? AND ?
                ORDER BY day_bucket, record_id
                LIMIT ?
                """,
                (query.start_day.isoformat(), query.end_day.isoformat(), query.limit),
            ).fetchall()
            return tuple(self._catalog_record_from_row(row) for row in rows)

    def _recover(self) -> RecoveryReport:
        with self._lock:
            self._require_open_locked()
            return self._recover_locked()

    def _recover_locked(self) -> RecoveryReport:
        self._quick_check_locked()
        temporary_removed = self._clean_temporary_locked()
        promoted = 0
        discarded = 0
        quarantined = 0
        completed_deletions = 0

        intents = self._connection.execute(
            "SELECT * FROM write_intents ORDER BY record_id"
        ).fetchall()
        for row in intents:
            token = cast(str, row["blob_token"])
            path = blob_path(self._paths, token)
            if not path.exists():
                with self._transaction_locked():
                    self._connection.execute(
                        "DELETE FROM write_intents WHERE record_id = ?", (row["record_id"],)
                    )
                discarded += 1
                continue
            try:
                blob = read_blob(self._paths, token, self._max_blob_bytes)
                self._verify_blob_digest(row, blob)
                envelope = decode_envelope(blob, max_blob_bytes=self._max_blob_bytes)
                self._verify_cross_reference(row, envelope, blob)
            except StorageFailure:
                if quarantine_path(self._paths, path):
                    quarantined += 1
                with self._transaction_locked():
                    self._connection.execute(
                        "DELETE FROM write_intents WHERE record_id = ?", (row["record_id"],)
                    )
                continue
            with self._transaction_locked():
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO records (
                        record_id, artifact_kind, envelope_schema_version, key_provider_id,
                        key_id, key_version, ciphertext_bytes, blob_bytes, day_bucket,
                        blob_token, blob_digest, state, migration_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)
                    """,
                    (
                        row["record_id"],
                        row["artifact_kind"],
                        row["envelope_schema_version"],
                        row["key_provider_id"],
                        row["key_id"],
                        row["key_version"],
                        row["ciphertext_bytes"],
                        row["blob_bytes"],
                        row["day_bucket"],
                        row["blob_token"],
                        row["blob_digest"],
                        CURRENT_STORAGE_SCHEMA_VERSION,
                    ),
                )
                self._connection.execute(
                    "DELETE FROM write_intents WHERE record_id = ?", (row["record_id"],)
                )
            promoted += 1

        deleting = self._connection.execute(
            "SELECT * FROM records WHERE state = 'deleting' ORDER BY record_id"
        ).fetchall()
        for row in deleting:
            path = blob_path(self._paths, cast(str, row["blob_token"]))
            safe_unlink(path)
            if path.parent.exists():
                fsync_directory(path.parent)
            with self._transaction_locked():
                self._connection.execute(
                    "DELETE FROM records WHERE record_id = ?", (row["record_id"],)
                )
            completed_deletions += 1

        ready_rows = self._connection.execute(
            "SELECT * FROM records WHERE state = 'ready' ORDER BY record_id"
        ).fetchall()
        for row in ready_rows:
            try:
                self._load_row_locked(row)
            except StorageFailure:
                self._quarantine_record_locked(row)
                quarantined += 1

        known_tokens = {
            cast(str, row[0])
            for row in self._connection.execute(
                "SELECT blob_token FROM records UNION SELECT blob_token FROM write_intents"
            ).fetchall()
        }
        for path in iter_blob_files(self._paths):
            token = path.relative_to(self._paths.blobs).as_posix()
            if token not in known_tokens and quarantine_path(self._paths, path):
                quarantined += 1

        ensure_catalog_permissions(self._paths)
        return RecoveryReport(
            promoted_write_intents=promoted,
            discarded_write_intents=discarded,
            temporary_files_removed=temporary_removed,
            quarantined_blobs=quarantined,
            completed_deletions=completed_deletions,
        )

    def _health_check(self) -> bool:
        with self._lock:
            self._require_open_locked()
            self._quick_check_locked()
            validate_current_schema(self._connection)
            ensure_catalog_permissions(self._paths)
            return True

    def _load_row_locked(self, row: sqlite3.Row) -> EncryptedRecordEnvelope:
        token = cast(str, row["blob_token"])
        blob = read_blob(self._paths, token, self._max_blob_bytes)
        self._verify_blob_digest(row, blob)
        envelope = decode_envelope(blob, max_blob_bytes=self._max_blob_bytes)
        self._verify_cross_reference(row, envelope, blob)
        return envelope

    def _verify_blob_digest(self, row: sqlite3.Row, blob: bytes) -> None:
        expected = cast(bytes, row["blob_digest"])
        if len(expected) != 32 or not hmac.compare_digest(hashlib.sha256(blob).digest(), expected):
            raise StorageFailure(
                StorageFailureCode.CORRUPTION,
                record_id=self._row_record_id(row),
            )

    def _verify_cross_reference(
        self,
        row: sqlite3.Row,
        envelope: EncryptedRecordEnvelope,
        blob: bytes,
    ) -> None:
        day_bucket = envelope.created_at.astimezone(UTC).date().isoformat()
        expected = (
            str(envelope.record_id),
            "capture-record",
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
                "artifact_kind",
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
        if actual != expected:
            raise StorageFailure(StorageFailureCode.CORRUPTION, record_id=envelope.record_id)

    def _quarantine_record_locked(self, row: sqlite3.Row) -> None:
        record_id = self._row_record_id(row)
        path = blob_path(self._paths, cast(str, row["blob_token"]))
        quarantine_path(self._paths, path)
        with self._transaction_locked():
            self._connection.execute(
                "UPDATE records SET state = 'quarantined' WHERE record_id = ?",
                (str(record_id),),
            )

    def _clean_temporary_locked(self) -> int:
        removed = 0
        for path in self._paths.temporary.iterdir():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
            if getattr(os, "getuid", None) is not None and info.st_uid != os.getuid():
                raise StorageFailure(StorageFailureCode.UNSAFE_ROOT)
            safe_unlink(path)
            removed += 1
        if removed:
            fsync_directory(self._paths.temporary)
        return removed

    def _quick_check_locked(self) -> None:
        try:
            rows = self._connection.execute("PRAGMA quick_check").fetchall()
        except sqlite3.DatabaseError as exc:
            raise StorageFailure(StorageFailureCode.CATALOG_FAILURE) from exc
        if [row[0] for row in rows] != ["ok"]:
            raise StorageFailure(StorageFailureCode.CATALOG_FAILURE)

    def _record_or_intent_exists_locked(self, record_id: UUID) -> bool:
        row = self._connection.execute(
            """
            SELECT 1 FROM records WHERE record_id = ?
            UNION ALL
            SELECT 1 FROM write_intents WHERE record_id = ?
            LIMIT 1
            """,
            (str(record_id), str(record_id)),
        ).fetchone()
        return row is not None

    @staticmethod
    def _catalog_record_from_row(row: sqlite3.Row) -> CatalogRecord:
        try:
            return CatalogRecord(
                record_id=UUID(cast(str, row["record_id"])),
                day_bucket=date.fromisoformat(cast(str, row["day_bucket"])),
                envelope_schema_version=cast(int, row["envelope_schema_version"]),
                key=KeyHandle(
                    key_id=cast(str, row["key_id"]),
                    provider_id=cast(str, row["key_provider_id"]),
                    version=cast(int, row["key_version"]),
                ),
                ciphertext_bytes=cast(int, row["ciphertext_bytes"]),
                blob_bytes=cast(int, row["blob_bytes"]),
            )
        except (ValueError, TypeError, KeyError, IndexError):
            raise StorageFailure(StorageFailureCode.CORRUPTION) from None

    @staticmethod
    def _intent_matches_values(row: sqlite3.Row, values: tuple[Any, ...]) -> bool:
        names = (
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
        )
        return tuple(row[name] for name in names) == values

    @contextmanager
    def _transaction_locked(self) -> Generator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        else:
            self._connection.execute("COMMIT")

    def _require_open_locked(self) -> None:
        if self._closed:
            raise RuntimeError("storage backend is closed")

    @staticmethod
    def _validate_record_id(record_id_value: object) -> UUID:
        if not isinstance(record_id_value, UUID) or record_id_value.version != 4:
            raise StorageFailure(StorageFailureCode.INVALID_RECORD_ID)
        return record_id_value

    @staticmethod
    def _require_envelope(value: object) -> EncryptedRecordEnvelope:
        if not isinstance(value, EncryptedRecordEnvelope):
            raise StorageFailure(StorageFailureCode.INVALID_TYPE)
        return value

    @staticmethod
    def _require_delete_request(value: object) -> DeleteRequest:
        if not isinstance(value, DeleteRequest):
            raise StorageFailure(StorageFailureCode.INVALID_TYPE)
        return value

    @staticmethod
    def _require_day_query(value: object) -> DayRangeQuery:
        if not isinstance(value, DayRangeQuery):
            raise StorageFailure(StorageFailureCode.INVALID_TYPE)
        return value

    @staticmethod
    def _row_record_id(row: sqlite3.Row) -> UUID:
        try:
            record_id = UUID(cast(str, row["record_id"]))
        except (ValueError, TypeError):
            raise StorageFailure(StorageFailureCode.CORRUPTION) from None
        if record_id.version != 4:
            raise StorageFailure(StorageFailureCode.CORRUPTION)
        return record_id
