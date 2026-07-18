from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from local_recall.domain.crypto import KeyHandle, KeyRequest, SecretKeyMaterial


class KeyHealthStatus(StrEnum):
    READY = "ready"
    LOCKED = "locked"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class KeyHealthReport:
    provider_id: str
    status: KeyHealthStatus
    key: KeyHandle | None = None

    @property
    def ready(self) -> bool:
        return self.status is KeyHealthStatus.READY


@dataclass(frozen=True, slots=True)
class KeyRotationRequest:
    current: KeyHandle
    reason_code: str


@dataclass(frozen=True, slots=True)
class KeyDestructionRequest:
    key: KeyHandle
    reason_code: str


@dataclass(frozen=True, slots=True)
class KeyDestructionResult:
    key: KeyHandle
    destroyed: bool


@dataclass(frozen=True, slots=True, repr=False)
class KeyWrapRequest:
    key: KeyHandle
    material: SecretKeyMaterial = field(repr=False)
    associated_data: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class KeyUnwrapRequest:
    key: KeyHandle
    wrapped_data_key: bytes = field(repr=False)
    associated_data: bytes = field(repr=False)


@runtime_checkable
class KeyProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    async def health(self, request: KeyRequest) -> KeyHealthReport: ...

    async def active_key(self, request: KeyRequest) -> KeyHandle: ...

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes: ...

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial: ...

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle: ...

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult: ...
