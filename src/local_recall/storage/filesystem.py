from __future__ import annotations

import hashlib
import os
import threading
from datetime import UTC
from pathlib import Path
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, StoredRecordRef
from local_recall.ports.keys import KeyProvider
from local_recall.ports.storage import DeleteRequest, DeleteResult

from ._catalog import StorageCatalog
from ._fs import (
    blob_token,
    fsync_directory,
    prepare_owner_directory,
    prepare_paths,
    safe_path,
    temporary_token,
    write_exclusive,
)
from ._operations import StorageOperations
from .codec import CURRENT_STORAGE_SCHEMA_VERSION, EncryptedBlobCodec
from .errors import StorageFailure, StorageFailureCode
from .models import StorageQuota, TimeRangeQuery

_BACKEND_ID = "filesystem-sqlite-v1"


class FilesystemStorageBackend:
    def __init__(
        self,
        root_directory: str | Path,
        key_provider: KeyProvider,
        *,
        quota: StorageQuota | None = None,
    ) -> None:
        self._paths = prepare_paths(root_directory)
        self._quota = quota or StorageQuota()
        self._codec = EncryptedBlobCodec(key_provider)
        self._catalog = StorageCatalog(self._paths.catalog)
        self._operations = StorageOperations(self._paths, self._catalog)
        self._lock = threading.RLock()
        self._operations.recover_pending()

    @property
    def backend_id(self) -> str:
        return _BACKEND_ID

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        if not isinstance(envelope, EncryptedRecordEnvelope):
            raise TypeError("storage accepts EncryptedRecordEnvelope only")
        blob = await self._codec.encode(envelope)
        digest = hashlib.sha256(blob).digest()
        record_id = envelope.record_id
        final_token = blob_token(record_id)
        temp_token = temporary_token(record_id)
        final_path = safe_path(self._paths, final_token)
        temp_path = safe_path(self._paths, temp_token)
        prepare_owner_directory(final_path.parent)

        with self._lock:
            self._operations.recover_pending()
            if self._catalog.select(record_id) is not None:
                raise StorageFailure(record_id, StorageFailureCode.RECORD_CONFLICT)
            self._catalog.check_quota(self._quota, len(blob))
            try:
                write_exclusive(temp_path, blob)
                self._catalog.insert_pending(
                    record_id=record_id,
                    storage_schema_version=CURRENT_STORAGE_SCHEMA_VERSION,
                    envelope_schema_version=envelope.schema_version,
                    key_id=envelope.key.key_id,
                    ciphertext_bytes=len(blob),
                    day_bucket=_day_bucket(envelope),
                    blob_token=final_token,
                    temp_token=temp_token,
                    blob_digest=digest,
                )
            except StorageFailure:
                temp_path.unlink(missing_ok=True)
                raise
            except OSError as exc:
                raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc

            try:
                os.replace(temp_path, final_path)
                fsync_directory(final_path.parent)
                self._catalog.mark_committed(record_id)
            except OSError as exc:
                raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc

        return StoredRecordRef(
            record_id=record_id,
            storage_id=final_token,
            envelope_schema_version=envelope.schema_version,
        )

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        with self._lock:
            self._operations.recover_pending()
            entry = self._catalog.select(record_id)
            if entry is None or entry.state != "committed":
                return None
            blob = self._operations.read_verified(entry)

        try:
            decoded = await self._codec.decode(blob, expected_record_id=record_id)
        except StorageFailure as exc:
            if exc.code is StorageFailureCode.CORRUPT_RECORD:
                with self._lock:
                    self._operations.quarantine_entry(entry)
            raise

        if decoded.requires_migration:
            replacement = await self._codec.encode(decoded.envelope)
            with self._lock:
                self._operations.replace_blob(entry, decoded.envelope, replacement)
        return decoded.envelope

    async def list_time_range(
        self,
        query: TimeRangeQuery,
    ) -> tuple[EncryptedRecordEnvelope, ...]:
        start_bucket = query.start_at.astimezone(UTC).date().isoformat()
        end_bucket = query.end_at.astimezone(UTC).date().isoformat()
        with self._lock:
            self._operations.recover_pending()
            record_ids = self._catalog.candidate_ids(start_bucket, end_bucket)

        matches: list[EncryptedRecordEnvelope] = []
        for record_id in record_ids:
            envelope = await self.get(record_id)
            if envelope is not None and query.start_at <= envelope.created_at < query.end_at:
                matches.append(envelope)
        matches.sort(key=lambda item: item.created_at)
        return tuple(matches[: query.limit])

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        with self._lock:
            self._operations.recover_pending()
            entry = self._catalog.select(request.record_id)
            if entry is None:
                return DeleteResult(request.record_id, False, False)
            final_path = safe_path(self._paths, entry.blob_token)
            temp_path = (
                safe_path(self._paths, entry.temp_token)
                if entry.temp_token is not None
                else None
            )
            try:
                final_path.unlink(missing_ok=True)
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
                fsync_directory(final_path.parent)
            except OSError as exc:
                raise StorageFailure(
                    request.record_id, StorageFailureCode.IO_FAILURE
                ) from exc
            self._catalog.delete(request.record_id)
        return DeleteResult(request.record_id, True, False)

    def close(self) -> None:
        with self._lock:
            self._catalog.close()


def _day_bucket(envelope: EncryptedRecordEnvelope) -> str:
    return envelope.created_at.astimezone(UTC).date().isoformat()
