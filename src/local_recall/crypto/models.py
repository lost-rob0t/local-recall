from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, KeyRequest
from local_recall.domain.lifecycle import CaptureGeneration


class KeyProviderState(StrEnum):
    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"
    LOCKED = "locked"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class KeyProviderHealth:
    provider_id: str
    state: KeyProviderState
    code: str

    @property
    def healthy(self) -> bool:
        return self.state is KeyProviderState.HEALTHY


@dataclass(frozen=True, slots=True)
class KeyDestructionResult:
    key: KeyHandle
    destroyed: bool


@runtime_checkable
class WrappingKeyProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    def health_check(self) -> KeyProviderHealth: ...

    def active_key(self, request: KeyRequest) -> KeyHandle: ...

    def wrap_data_key(self, key: KeyHandle, data_key: bytes, associated_data: bytes) -> bytes: ...

    def unwrap_data_key(
        self, key: KeyHandle, wrapped_data_key: bytes, associated_data: bytes
    ) -> bytearray: ...

    def rotate(self, current: KeyHandle, reason_code: str) -> KeyHandle: ...

    def destroy(self, key: KeyHandle, reason_code: str) -> KeyDestructionResult: ...


@dataclass(frozen=True, slots=True)
class KeyProviderSelection:
    provider: WrappingKeyProvider = field(repr=False)
    key: KeyHandle
    used_fallback: bool


@dataclass(frozen=True, slots=True, repr=False)
class DecryptedRecordPayload:
    record_id: UUID
    generation: CaptureGeneration
    configuration_revision: str
    created_at: datetime
    frames: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class RewrapResult:
    envelope: EncryptedRecordEnvelope
    changed: bool
    used_fallback: bool
