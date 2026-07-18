from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope

from ._catalog import StorageCatalog
from ._catalog_schema import CatalogEntry
from ._fs import (
    StoragePaths,
    fsync_directory,
    matches_digest,
    safe_path,
    temporary_token,
    write_exclusive,
)
from .codec import CURRENT_STORAGE_SCHEMA_VERSION
from .errors import StorageFailure, StorageFailureCode


class StorageOperations:
    def __init__(self, paths: StoragePaths, catalog: StorageCatalog) -> None:
        self.paths = paths
        self.catalog = catalog

    def read_verified(self, entry: CatalogEntry) -> bytes:
        path = safe_path(self.paths, entry.blob_token)
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise StorageFailure(entry.record_id, StorageFailureCode.IO_FAILURE) from exc
        if len(blob) != entry.ciphertext_bytes or not secrets.compare_digest(
            hashlib.sha256(blob).digest(),
            entry.blob_digest,
        ):
            self.quarantine_entry(entry)
            raise StorageFailure(entry.record_id, StorageFailureCode.CORRUPT_RECORD)
        return blob

    def replace_blob(
        self,
        entry: CatalogEntry,
        envelope: EncryptedRecordEnvelope,
        blob: bytes,
    ) -> None:
        final_path = safe_path(self.paths, entry.blob_token)
        temp_token = temporary_token(entry.record_id)
        temp_path = safe_path(self.paths, temp_token)
        digest = hashlib.sha256(blob).digest()
        try:
            write_exclusive(temp_path, blob)
            self.catalog.begin_replacement(
                entry,
                storage_schema_version=CURRENT_STORAGE_SCHEMA_VERSION,
                envelope_schema_version=envelope.schema_version,
                key_id=envelope.key.key_id,
                ciphertext_bytes=len(blob),
                temp_token=temp_token,
                blob_digest=digest,
            )
            os.replace(temp_path, final_path)
            fsync_directory(final_path.parent)
            self.catalog.mark_committed(entry.record_id)
        except StorageFailure:
            temp_path.unlink(missing_ok=True)
            raise
        except OSError as exc:
            raise StorageFailure(entry.record_id, StorageFailureCode.IO_FAILURE) from exc

    def recover_pending(self) -> None:
        referenced_temps: set[str] = set()
        for entry in self.catalog.pending():
            final_path = safe_path(self.paths, entry.blob_token)
            temp_path = (
                safe_path(self.paths, entry.temp_token)
                if entry.temp_token is not None
                else None
            )
            if entry.temp_token is not None:
                referenced_temps.add(entry.temp_token)
            try:
                if temp_path is not None and temp_path.exists():
                    if not matches_digest(
                        temp_path, entry.ciphertext_bytes, entry.blob_digest
                    ):
                        self.quarantine_entry(entry, source=temp_path)
                        continue
                    os.replace(temp_path, final_path)
                    fsync_directory(final_path.parent)
                    self.catalog.mark_committed(entry.record_id)
                    continue
                if final_path.exists():
                    if not matches_digest(
                        final_path, entry.ciphertext_bytes, entry.blob_digest
                    ):
                        self.quarantine_entry(entry, source=final_path)
                        continue
                    self.catalog.mark_committed(entry.record_id)
                    continue
                self.catalog.delete(entry.record_id)
            except StorageFailure:
                raise
            except OSError as exc:
                raise StorageFailure(
                    entry.record_id, StorageFailureCode.IO_FAILURE
                ) from exc

        for path in self.paths.blobs.rglob("*"):
            if not path.is_file() or ".tmp-" not in path.name:
                continue
            token = path.relative_to(self.paths.root).as_posix()
            if token not in referenced_temps:
                self.quarantine_path(path)

    def quarantine_entry(
        self,
        entry: CatalogEntry,
        *,
        source: Path | None = None,
    ) -> None:
        source_path = source or safe_path(self.paths, entry.blob_token)
        destination = self.quarantine_path(source_path, record_id=entry.record_id)
        self.catalog.mark_quarantined(
            entry.record_id, destination.relative_to(self.paths.root).as_posix()
        )

    def quarantine_path(
        self,
        source: Path,
        *,
        record_id: UUID | None = None,
    ) -> Path:
        identity = "orphan" if record_id is None else record_id.hex
        destination = self.paths.quarantine / f"{identity}-{secrets.token_hex(8)}.lre"
        try:
            if source.exists():
                os.replace(source, destination)
                fsync_directory(self.paths.quarantine)
        except OSError as exc:
            raise StorageFailure(record_id, StorageFailureCode.IO_FAILURE) from exc
        return destination
