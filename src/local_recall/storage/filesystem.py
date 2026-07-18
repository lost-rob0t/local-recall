from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
import threading
from datetime import UTC
from pathlib import Path, PurePosixPath
from typing import Any, cast
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, StoredRecordRef
from local_recall.ports.keys import KeyProvider
from local_recall.ports.storage import DeleteRequest, DeleteResult

from .codec import CURRENT_STORAGE_SCHEMA_VERSION, EncryptedBlobCodec
from .errors import StorageFailure, StorageFailureCode
from .models import StorageQuota, TimeRangeQuery

_CATALOG_SCHEMA_VERSION = 1
_BACKEND_ID = "filesystem-sqlite-v1"


type _CatalogRow = tuple[
    str,
    int,
    int,
    str,
    int,
    str,
    str | None,
    bytes,
    str,
]


class FilesystemStorageBackend:
    def __init__(
        self,
        root_directory: str | Path,
        key_provider: KeyProvider,
        *,
        quota: StorageQuota | None = None,
    ) -> None:
        self._root = Path(root_directory)
        _reject_symlink_components(self._root)
        _prepare_owner_directory(self._root)
        self._resolved_root = self._root.resolve(strict=True)
        self._blobs = self._root / "blobs"
        self._quarantine = self._root / "quarantine"
        _prepare_owner_directory(self._blobs)
        _prepare_owner_directory(self._quarantine)
        self._catalog_path = self._root / "catalog.sqlite3"
        _prepare_owner_file(self._catalog_path)
        self._quota = quota or StorageQuota()
        self._codec = EncryptedBlobCodec(key_provider)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self._catalog_path, timeout=5.0)
        self._connection.execute("PRAGMA journal_mode = DELETE")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA temp_store = MEMORY")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        self._initialize_catalog()
        self._recover_pending()

    @property
    def backend_id(self) -> str:
        return _BACKEND_ID

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        if not isinstance(envelope, EncryptedRecordEnvelope):
            raise TypeError("storage accepts EncryptedRecordEnvelope only")
        blob = await self._codec.encode(envelope)
        digest = hashlib.sha256(blob).digest()
        record_id = envelope.record_id
        blob_token = _blob_token(record_id)
        temp_token = _temporary_token(record_id)
        final_path = self._safe_path(blob_token)
        temp_path = self._safe_path(temp_token)
        _prepare_owner_directory(final_path.parent)

        with self._lock:
            self._recover_pending()
            if self._select_row(record_id) is not None:
                raise StorageFailure(record_id, StorageFailureCode.RECORD_CONFLICT)
            self._check_quota(len(blob))
            try:
                _write_exclusive(temp_path, blob)
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT INTO records (
                            record_id,
                            storage_schema_version,
                            envelope_schema_version,
                            key_id,
                            ciphertext_bytes,
                            day_bucket,
                            blob_token,
                            temp_token,
                            blob_digest,
                            state,
                            migration_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0)
                        """,
                        (
                            str(record_id),
                            CURRENT_STORAGE_SCHEMA_VERSION,
                            envelope.schema_version,
                            envelope.key.key_id,
                            len(blob),
                            _day_bucket(envelope),
                            blob_token,
                            temp_token,
                            digest,
                        ),
                    )
            except sqlite3.Error as exc:
                temp_path.unlink(missing_ok=True)
                raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc
            except OSError as exc:
                raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc

            try:
                os.replace(temp_path, final_path)
                _fsync_directory(final_path.parent)
            except OSError as exc:
                raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc

            try:
                with self._connection:
                    self._connection.execute(
                        "UPDATE records SET state = 'committed', temp_token = NULL "
                        "WHERE record_id = ?",
                        (str(record_id),),
                    )
            except sqlite3.Error as exc:
                raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc

        return StoredRecordRef(
            record_id=record_id,
            storage_id=blob_token,
            envelope_schema_version=envelope.schema_version,
        )

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        with self._lock:
            self._recover_pending()
            row = self._select_row(record_id)
            if row is None or row[8] != "committed":
                return None
            blob = self._read_verified_blob(row)

        try:
            decoded = await self._codec.decode(blob, expected_record_id=record_id)
        except StorageFailure:
            with self._lock:
                self._quarantine_row(row)
            raise

        if decoded.requires_migration:
            replacement = await self._codec.encode(decoded.envelope)
            with self._lock:
                self._replace_blob(row, decoded.envelope, replacement)
        return decoded.envelope

    async def list_time_range(
        self,
        query: TimeRangeQuery,
    ) -> tuple[EncryptedRecordEnvelope, ...]:
        start_bucket = query.start_at.astimezone(UTC).date().isoformat()
        end_bucket = query.end_at.astimezone(UTC).date().isoformat()
        with self._lock:
            self._recover_pending()
            try:
                rows = self._connection.execute(
                    """
                    SELECT record_id
                    FROM records
                    WHERE state = 'committed' AND day_bucket >= ? AND day_bucket <= ?
                    ORDER BY day_bucket, record_id
                    """,
                    (start_bucket, end_bucket),
                ).fetchall()
            except sqlite3.Error as exc:
                raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc

        matches: list[EncryptedRecordEnvelope] = []
        for raw_row in rows:
            record_id_text = cast(tuple[Any, ...], raw_row)[0]
            record_id = UUID(cast(str, record_id_text))
            envelope = await self.get(record_id)
            if envelope is None:
                continue
            if query.start_at <= envelope.created_at < query.end_at:
                matches.append(envelope)
        matches.sort(key=lambda item: item.created_at)
        return tuple(matches[: query.limit])

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        with self._lock:
            self._recover_pending()
            row = self._select_row(request.record_id)
            if row is None:
                return DeleteResult(
                    record_id=request.record_id,
                    deleted=False,
                    cryptographic_material_destroyed=False,
                )
            final_path = self._safe_path(row[5])
            temp_path = self._safe_path(row[6]) if row[6] is not None else None
            try:
                final_path.unlink(missing_ok=True)
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
                _fsync_directory(final_path.parent)
            except OSError as exc:
                raise StorageFailure(request.record_id, StorageFailureCode.IO_FAILURE) from exc
            try:
                with self._connection:
                    self._connection.execute(
                        "DELETE FROM records WHERE record_id = ?",
                        (str(request.record_id),),
                    )
            except sqlite3.Error as exc:
                raise StorageFailure(
                    request.record_id,
                    StorageFailureCode.CATALOG_FAILURE,
                ) from exc
        return DeleteResult(
            record_id=request.record_id,
            deleted=True,
            cryptographic_material_destroyed=False,
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _initialize_catalog(self) -> None:
        try:
            with self._connection:
                self._connection.executescript(
                    """
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
                )
                version_row = self._connection.execute("PRAGMA user_version").fetchone()
                version = 0 if version_row is None else int(version_row[0])
                if version > _CATALOG_SCHEMA_VERSION:
                    raise StorageFailure(None, StorageFailureCode.UNSUPPORTED_SCHEMA)
                self._connection.execute(f"PRAGMA user_version = {_CATALOG_SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc

    def _select_row(self, record_id: UUID) -> _CatalogRow | None:
        try:
            row = self._connection.execute(
                """
                SELECT
                    record_id,
                    storage_schema_version,
                    envelope_schema_version,
                    key_id,
                    ciphertext_bytes,
                    blob_token,
                    temp_token,
                    blob_digest,
                    state
                FROM records
                WHERE record_id = ?
                """,
                (str(record_id),),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc
        return None if row is None else cast(_CatalogRow, row)

    def _check_quota(self, additional_bytes: int) -> None:
        try:
            row = self._connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(ciphertext_bytes), 0)
                FROM records
                WHERE state IN ('pending', 'committed', 'quarantined')
                """
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc
        if row is None:
            count = 0
            used_bytes = 0
        else:
            values = cast(tuple[Any, ...], row)
            count = int(values[0])
            used_bytes = int(values[1])
        if count + 1 > self._quota.max_records:
            raise StorageFailure(None, StorageFailureCode.QUOTA_EXCEEDED)
        if used_bytes + additional_bytes > self._quota.max_bytes:
            raise StorageFailure(None, StorageFailureCode.QUOTA_EXCEEDED)

    def _read_verified_blob(self, row: _CatalogRow) -> bytes:
        record_id = UUID(row[0])
        path = self._safe_path(row[5])
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc
        if len(blob) != row[4] or not secrets.compare_digest(
            hashlib.sha256(blob).digest(),
            row[7],
        ):
            self._quarantine_row(row)
            raise StorageFailure(record_id, StorageFailureCode.CORRUPT_RECORD)
        return blob

    def _replace_blob(
        self,
        row: _CatalogRow,
        envelope: EncryptedRecordEnvelope,
        blob: bytes,
    ) -> None:
        record_id = envelope.record_id
        final_path = self._safe_path(row[5])
        temp_token = _temporary_token(record_id)
        temp_path = self._safe_path(temp_token)
        digest = hashlib.sha256(blob).digest()
        try:
            _write_exclusive(temp_path, blob)
            with self._connection:
                self._connection.execute(
                    """
                    UPDATE records
                    SET
                        storage_schema_version = ?,
                        envelope_schema_version = ?,
                        key_id = ?,
                        ciphertext_bytes = ?,
                        temp_token = ?,
                        blob_digest = ?,
                        state = 'pending',
                        migration_version = migration_version + 1
                    WHERE record_id = ?
                    """,
                    (
                        CURRENT_STORAGE_SCHEMA_VERSION,
                        envelope.schema_version,
                        envelope.key.key_id,
                        len(blob),
                        temp_token,
                        digest,
                        str(record_id),
                    ),
                )
        except sqlite3.Error as exc:
            temp_path.unlink(missing_ok=True)
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc
        except OSError as exc:
            raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc
        try:
            os.replace(temp_path, final_path)
            _fsync_directory(final_path.parent)
            with self._connection:
                self._connection.execute(
                    "UPDATE records SET state = 'committed', temp_token = NULL "
                    "WHERE record_id = ?",
                    (str(record_id),),
                )
        except sqlite3.Error as exc:
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc
        except OSError as exc:
            raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc

    def _recover_pending(self) -> None:
        try:
            pending_rows = self._connection.execute(
                """
                SELECT
                    record_id,
                    storage_schema_version,
                    envelope_schema_version,
                    key_id,
                    ciphertext_bytes,
                    blob_token,
                    temp_token,
                    blob_digest,
                    state
                FROM records
                WHERE state = 'pending'
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE) from exc

        referenced_temps: set[str] = set()
        for raw_row in pending_rows:
            row = cast(_CatalogRow, raw_row)
            record_id = UUID(row[0])
            final_path = self._safe_path(row[5])
            temp_path = self._safe_path(row[6]) if row[6] is not None else None
            if row[6] is not None:
                referenced_temps.add(row[6])
            try:
                if temp_path is not None and temp_path.exists():
                    if not _matches_digest(temp_path, row[4], row[7]):
                        self._quarantine_row(row, source=temp_path)
                        continue
                    os.replace(temp_path, final_path)
                    _fsync_directory(final_path.parent)
                    self._mark_committed(record_id)
                    continue
                if final_path.exists():
                    if not _matches_digest(final_path, row[4], row[7]):
                        self._quarantine_row(row, source=final_path)
                        continue
                    self._mark_committed(record_id)
                    continue
                with self._connection:
                    self._connection.execute(
                        "DELETE FROM records WHERE record_id = ?",
                        (str(record_id),),
                    )
            except sqlite3.Error as exc:
                raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc
            except OSError as exc:
                raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc

        for path in self._blobs.rglob("*"):
            if not path.is_file() or ".tmp-" not in path.name:
                continue
            token = path.relative_to(self._root).as_posix()
            if token not in referenced_temps:
                self._quarantine_path(path)

    def _mark_committed(self, record_id: UUID) -> None:
        with self._connection:
            self._connection.execute(
                "UPDATE records SET state = 'committed', temp_token = NULL "
                "WHERE record_id = ?",
                (str(record_id),),
            )

    def _quarantine_row(
        self,
        row: _CatalogRow,
        *,
        source: Path | None = None,
    ) -> None:
        record_id = UUID(row[0])
        source_path = source or self._safe_path(row[5])
        quarantine_path = self._quarantine_path(source_path, record_id=record_id)
        try:
            with self._connection:
                self._connection.execute(
                    """
                    UPDATE records
                    SET state = 'quarantined', blob_token = ?, temp_token = NULL
                    WHERE record_id = ?
                    """,
                    (quarantine_path.relative_to(self._root).as_posix(), str(record_id)),
                )
        except sqlite3.Error as exc:
            raise StorageFailure(record_id, StorageFailureCode.CATALOG_FAILURE) from exc

    def _quarantine_path(
        self,
        source: Path,
        *,
        record_id: UUID | None = None,
    ) -> Path:
        identity = "orphan" if record_id is None else record_id.hex
        destination = self._quarantine / f"{identity}-{secrets.token_hex(8)}.lre"
        try:
            if source.exists():
                os.replace(source, destination)
                _fsync_directory(self._quarantine)
        except OSError as exc:
            raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc
        return destination

    def _safe_path(self, token: str | None) -> Path:
        if token is None:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE)
        relative = PurePosixPath(token)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE)
        candidate = self._root.joinpath(*relative.parts)
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(self._resolved_root):
            raise StorageFailure(None, StorageFailureCode.CATALOG_FAILURE)
        return candidate


def _day_bucket(envelope: EncryptedRecordEnvelope) -> str:
    return envelope.created_at.astimezone(UTC).date().isoformat()


def _blob_token(record_id: UUID) -> str:
    value = record_id.hex
    return f"blobs/{value[:2]}/{value}.lre"


def _temporary_token(record_id: UUID) -> str:
    value = record_id.hex
    return f"blobs/{value[:2]}/.{value}.tmp-{secrets.token_hex(8)}"


def _matches_digest(path: Path, expected_size: int, expected_digest: bytes) -> bool:
    try:
        value = path.read_bytes()
    except OSError:
        return False
    return len(value) == expected_size and secrets.compare_digest(
        hashlib.sha256(value).digest(),
        expected_digest,
    )


def _prepare_owner_directory(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("storage directory must be a real directory")
    else:
        path.mkdir(parents=True, mode=0o700)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("storage directory must be owner-only")


def _prepare_owner_file(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError("storage catalog must be a regular file")
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("storage catalog must be owner-only")


def _reject_symlink_components(path: Path) -> None:
    current = path
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise ValueError("storage paths must not contain symlinks")
        current = current.parent


def _write_exclusive(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(value)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
