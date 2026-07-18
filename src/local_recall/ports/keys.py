from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from local_recall.domain.crypto import KeyHandle, KeyRequest


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


@runtime_checkable
class KeyProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    async def active_key(self, request: KeyRequest) -> KeyHandle: ...

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle: ...

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult: ...
