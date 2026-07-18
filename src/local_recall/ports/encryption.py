from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar, runtime_checkable

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.frames import RedactedRecord

RecordT = TypeVar("RecordT", bound=RedactedRecord)


@dataclass(frozen=True, slots=True)
class EncryptionRequest(Generic[RecordT]):
    record: RecordT
    key: KeyHandle
    schema_version: int


@dataclass(frozen=True, slots=True)
class DecryptionRequest:
    envelope: EncryptedRecordEnvelope
    key: KeyHandle


@runtime_checkable
class EncryptionProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    async def encrypt(
        self, request: EncryptionRequest[RedactedRecord]
    ) -> EncryptedRecordEnvelope: ...

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord: ...
