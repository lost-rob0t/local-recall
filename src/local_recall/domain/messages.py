from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

from ._validation import require_aware, require_nonempty
from .lifecycle import CaptureGeneration
from .privacy import PrivacyClass

PayloadT = TypeVar("PayloadT", covariant=True)


@dataclass(frozen=True, slots=True)
class MessageHeader:
    protocol_version: int
    message_type: str
    message_id: UUID
    correlation_id: UUID | None
    generation: CaptureGeneration | None
    configuration_revision: str
    deadline_monotonic_ns: int
    privacy_class: PrivacyClass
    declared_payload_bytes: int

    def __post_init__(self) -> None:
        if self.protocol_version <= 0:
            raise ValueError("protocol version must be positive")
        require_nonempty(self.message_type, "message_type")
        require_nonempty(self.configuration_revision, "configuration_revision")
        if self.deadline_monotonic_ns <= 0:
            raise ValueError("deadline must be positive")
        if self.declared_payload_bytes < 0:
            raise ValueError("declared payload bytes must be non-negative")


@dataclass(frozen=True, slots=True)
class MessageEnvelope(Generic[PayloadT]):
    header: MessageHeader
    payload: PayloadT


@dataclass(frozen=True, slots=True)
class EventEnvelope(Generic[PayloadT]):
    event_id: UUID
    event_type: str
    occurred_at: datetime
    payload: PayloadT

    def __post_init__(self) -> None:
        require_nonempty(self.event_type, "event_type")
        require_aware(self.occurred_at, "occurred_at")
