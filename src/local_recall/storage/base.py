# pyright: reportUnusedClass=false
from __future__ import annotations

import asyncio
import sqlite3
import threading
from collections.abc import Callable
from datetime import date
from pathlib import Path
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, StoredRecordRef
from local_recall.ports.storage import (
    CatalogPage,
    CatalogRecord,
    DayRangeQuery,
    DeleteRequest,
    DeleteResult,
    StorageIntegrityReport,
    StorageUsageReport,
)

from .errors import StorageFailure, StorageFailureCode
from .filesystem import StoragePaths, ensure_catalog_permissions, prepare_paths
from .schema import configure_connection, migrate_catalog


class _SQLiteStorageBase:
    backend_id = "sqlite-opaque-files"

    def __init__(
        self,
        root: Path,
        *,
        quota_bytes: int = 10 * 1024 * 1024 * 1024,
        max_blob_bytes: int = 256 * 1024 * 1024,
        busy_timeout_seconds: float = 5.0,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        if quota_bytes <= 0:
            raise ValueError("quota_bytes must be positive")
        if not 1024 <= max_blob_bytes <= quota_bytes:
            raise ValueError("max_blob_bytes must be between 1024 and quota_bytes")
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")
        self._quota_bytes = quota_bytes
        self._max_blob_bytes = max_blob_bytes
        self._fault_injector = fault_injector
        self._lock = threading.RLock()
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
            migrate_catalog(self._connection, self._paths, self._max_blob_bytes)
            ensure_catalog_permissions(self._paths)
            self._recover_sync()
        except StorageFailure:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise StorageFailure(StorageFailureCode.CATALOG_FAILURE) from exc

    @property
    def paths(self) -> StoragePaths:
        return self._paths

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        if type(envelope) is not EncryptedRecordEnvelope:
            raise StorageFailure(StorageFailureCode.INVALID_TYPE)
        return await asyncio.to_thread(self._put_sync, envelope)

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        return await asyncio.to_thread(self._get_sync, record_id)

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        return await asyncio.to_thread(self._delete_sync, request)

    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        return await asyncio.to_thread(self._list_candidates_sync, request)

    async def recover(self) -> StorageIntegrityReport:
        return await asyncio.to_thread(self._recover_sync)

    async def stats(self) -> StorageUsageReport:
        return await asyncio.to_thread(self._stats_sync)

    async def page_ready(
        self,
        *,
        after_day: date | None = None,
        after_id: UUID | None = None,
        limit: int,
    ) -> CatalogPage:
        return await asyncio.to_thread(
            self._page_ready_sync,
            after_day=after_day.isoformat() if after_day is not None else None,
            after_id=after_id,
            limit=limit,
        )

    async def close(self) -> None:
        await asyncio.to_thread(self.close_sync)

    def close_sync(self) -> None:
        with self._lock:
            self._connection.close()

    def _transaction(self, statement: str, parameters: tuple[object, ...]) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(statement, parameters)
            self._connection.execute("COMMIT")
        except Exception:
            self._rollback()
            raise

    def _rollback(self) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")

    def _fault(self, point: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(point)

    def _put_sync(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        raise NotImplementedError

    def _get_sync(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        raise NotImplementedError

    def _delete_sync(self, request: DeleteRequest) -> DeleteResult:
        raise NotImplementedError

    def _list_candidates_sync(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        raise NotImplementedError

    def _recover_sync(self) -> StorageIntegrityReport:
        raise NotImplementedError
