from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Protocol, runtime_checkable
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, StoredRecordRef


@dataclass(frozen=True, slots=True)
class DeleteRequest:
    record_id: UUID
    reason_code: str

    def __post_init__(self) -> None:
        if not self.reason_code:
            raise ValueError("reason_code must not be empty")


@dataclass(frozen=True, slots=True)
class DeleteResult:
    record_id: UUID
    deleted: bool
    cryptographic_material_destroyed: bool


@dataclass(frozen=True, slots=True)
class DayRangeQuery:
    start_day: date
    end_day: date
    limit: int = 1024

    def __post_init__(self) -> None:
        if self.end_day < self.start_day:
            raise ValueError("end_day precedes start_day")
        if not 1 <= self.limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")


@dataclass(frozen=True, slots=True)
class CatalogRecord:
    record: StoredRecordRef
    day_bucket: date
    blob_bytes: int
    key_provider_id: str
    key_id: str
    key_version: int

    def __post_init__(self) -> None:
        if self.blob_bytes <= 0:
            raise ValueError("blob_bytes must be positive")
        if not self.key_provider_id or not self.key_id:
            raise ValueError("key identifiers must not be empty")
        if self.key_version <= 0:
            raise ValueError("key_version must be positive")


@dataclass(frozen=True, slots=True)
class StorageIntegrityReport:
    verified_records: int = 0
    recovered_writes: int = 0
    removed_temporary_files: int = 0
    completed_deletions: int = 0
    quarantined_records: int = 0
    indexed_orphans: int = 0

    def __post_init__(self) -> None:
        values = (
            self.verified_records,
            self.recovered_writes,
            self.removed_temporary_files,
            self.completed_deletions,
            self.quarantined_records,
            self.indexed_orphans,
        )
        if any(value < 0 for value in values):
            raise ValueError("integrity report counts must be non-negative")


@runtime_checkable
class StorageBackend(Protocol):
    @property
    def backend_id(self) -> str: ...

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef: ...

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None: ...

    async def delete(self, request: DeleteRequest) -> DeleteResult: ...


@runtime_checkable
class QueryableStorageBackend(StorageBackend, Protocol):
    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]: ...

    async def recover(self) -> StorageIntegrityReport: ...
