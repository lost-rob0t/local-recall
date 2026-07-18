# pyright: reportPrivateUsage=false
from __future__ import annotations

import hashlib
from typing import cast

from local_recall.ports.storage import StorageIntegrityReport

from .codec import decode_envelope
from .errors import StorageFailure, StorageFailureCode
from .filesystem import (
    blob_path,
    blob_token,
    ensure_catalog_permissions,
    iter_blob_files,
    quarantine_path,
    read_blob,
    read_regular_file,
    safe_unlink,
)
from .models import CatalogState
from .operations import _RECORD_INSERT, _SQLiteStorageOperations
from .schema import CURRENT_STORAGE_SCHEMA_VERSION


class SQLiteEncryptedStorage(_SQLiteStorageOperations):
    def _recover_sync(self) -> StorageIntegrityReport:
        counts = {
            "verified": 0,
            "recovered": 0,
            "temps": 0,
            "deletions": 0,
            "quarantined": 0,
            "orphans": 0,
        }
        with self._lock:
            for temporary in self._paths.temporary.glob("*.tmp"):
                safe_unlink(temporary)
                counts["temps"] += 1
            self._recover_intents(counts)
            self._recover_deletions(counts)
            self._verify_ready(counts)
            self._recover_orphans(counts)
            ensure_catalog_permissions(self._paths)
        return StorageIntegrityReport(
            verified_records=counts["verified"],
            recovered_writes=counts["recovered"],
            removed_temporary_files=counts["temps"],
            completed_deletions=counts["deletions"],
            quarantined_records=counts["quarantined"],
            indexed_orphans=counts["orphans"],
        )

    def _recover_intents(self, counts: dict[str, int]) -> None:
        rows = self._connection.execute("SELECT * FROM write_intents ORDER BY record_id")
        for row in rows.fetchall():
            token = cast(str, row["blob_token"])
            path = blob_path(self._paths, token)
            if not path.exists():
                self._connection.execute(
                    "DELETE FROM write_intents WHERE record_id = ?", (row["record_id"],)
                )
                continue
            try:
                blob = read_blob(self._paths, token, self._max_blob_bytes)
                envelope = decode_envelope(blob, max_blob_bytes=self._max_blob_bytes)
                if (
                    hashlib.sha256(blob).digest() != cast(bytes, row["blob_digest"])
                    or str(envelope.record_id) != row["record_id"]
                ):
                    raise StorageFailure(StorageFailureCode.CORRUPTION)
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "INSERT OR IGNORE INTO records VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)",
                    (*tuple(row), CURRENT_STORAGE_SCHEMA_VERSION),
                )
                self._connection.execute(
                    "DELETE FROM write_intents WHERE record_id = ?", (row["record_id"],)
                )
                self._connection.execute("COMMIT")
                counts["recovered"] += 1
            except Exception:
                self._rollback()
                quarantine_path(self._paths, path)
                self._connection.execute(
                    "DELETE FROM write_intents WHERE record_id = ?", (row["record_id"],)
                )
                counts["quarantined"] += 1

    def _recover_deletions(self, counts: dict[str, int]) -> None:
        rows = self._connection.execute(
            "SELECT record_id, blob_token FROM records WHERE state = 'deleting'"
        )
        for row in rows.fetchall():
            safe_unlink(blob_path(self._paths, cast(str, row["blob_token"])))
            self._connection.execute("DELETE FROM records WHERE record_id = ?", (row["record_id"],))
            counts["deletions"] += 1

    def _verify_ready(self, counts: dict[str, int]) -> None:
        rows = self._connection.execute(
            "SELECT * FROM records WHERE state = 'ready' ORDER BY record_id"
        )
        for row in rows.fetchall():
            try:
                self._decode_row(row)
                counts["verified"] += 1
            except Exception:
                self._quarantine_row(row)
                counts["quarantined"] += 1

    def _recover_orphans(self, counts: dict[str, int]) -> None:
        referenced = {
            cast(str, row[0])
            for row in self._connection.execute(
                "SELECT blob_token FROM records UNION SELECT blob_token FROM write_intents"
            )
        }
        for path in iter_blob_files(self._paths):
            token = f"{path.parent.name}/{path.name}"
            if token in referenced:
                continue
            try:
                blob = read_regular_file(path, self._max_blob_bytes)
                envelope = decode_envelope(blob, max_blob_bytes=self._max_blob_bytes)
                if token != blob_token(envelope.record_id):
                    raise StorageFailure(StorageFailureCode.CORRUPTION)
                metadata = self._metadata(envelope, blob, token, hashlib.sha256(blob).digest())
                self._connection.execute(
                    _RECORD_INSERT,
                    (*metadata, CatalogState.READY.value, CURRENT_STORAGE_SCHEMA_VERSION),
                )
                counts["orphans"] += 1
            except Exception:
                quarantine_path(self._paths, path)
                counts["quarantined"] += 1
