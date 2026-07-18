from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, StoredRecordRef


@dataclass(frozen=True, slots=True)
class DeleteRequest:
    record_id: UUID
    reason_code: str


@dataclass(frozen=True, slots=True)
class DeleteResult:
    record_id: UUID
    deleted: bool
    cryptographic_material_destroyed: bool


@runtime_checkable
class StorageBackend(Protocol):
    @property
    def backend_id(self) -> str: ...

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef: ...

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None: ...

    async def delete(self, request: DeleteRequest) -> DeleteResult: ...
