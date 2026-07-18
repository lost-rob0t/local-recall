from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from ._validation import require_aware


class CaptureState(StrEnum):
    OFF = "off"
    STARTING = "starting"
    RECORDING = "recording"
    PAUSED = "paused"
    PRIVACY = "privacy"
    STOPPING = "stopping"
    FAULTED = "faulted"


class TransitionReason(StrEnum):
    USER_START = "user_start"
    USER_STOP = "user_stop"
    USER_PAUSE = "user_pause"
    USER_RESUME = "user_resume"
    PRIVACY_ENABLED = "privacy_enabled"
    PRIVACY_DISABLED = "privacy_disabled"
    SESSION_LOCKED = "session_locked"
    SESSION_UNLOCKED = "session_unlocked"
    IDLE = "idle"
    ACTIVE = "active"
    CRITICAL_FAULT = "critical_fault"
    STARTUP_SAFE_DEFAULT = "startup_safe_default"
    SHUTDOWN = "shutdown"


@dataclass(frozen=True, slots=True, order=True)
class CaptureGeneration:
    value: int

    def __post_init__(self) -> None:
        if self.value <= 0:
            raise ValueError("capture generation must be positive")


_ALLOWED_TRANSITIONS: dict[CaptureState, frozenset[CaptureState]] = {
    CaptureState.OFF: frozenset({CaptureState.STARTING}),
    CaptureState.STARTING: frozenset(
        {CaptureState.RECORDING, CaptureState.OFF, CaptureState.FAULTED}
    ),
    CaptureState.RECORDING: frozenset(
        {
            CaptureState.PAUSED,
            CaptureState.PRIVACY,
            CaptureState.STOPPING,
            CaptureState.FAULTED,
        }
    ),
    CaptureState.PAUSED: frozenset(
        {
            CaptureState.RECORDING,
            CaptureState.PRIVACY,
            CaptureState.STOPPING,
            CaptureState.OFF,
            CaptureState.FAULTED,
        }
    ),
    CaptureState.PRIVACY: frozenset(
        {
            CaptureState.RECORDING,
            CaptureState.PAUSED,
            CaptureState.STOPPING,
            CaptureState.OFF,
            CaptureState.FAULTED,
        }
    ),
    CaptureState.STOPPING: frozenset({CaptureState.OFF, CaptureState.FAULTED}),
    CaptureState.FAULTED: frozenset({CaptureState.OFF}),
}


@dataclass(frozen=True, slots=True)
class CaptureStateTransition:
    previous: CaptureState
    current: CaptureState
    generation: CaptureGeneration
    reason: TransitionReason
    occurred_at: datetime
    event_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        require_aware(self.occurred_at, "occurred_at")
        if self.current not in _ALLOWED_TRANSITIONS[self.previous]:
            raise ValueError(
                f"invalid capture transition: {self.previous.value} -> {self.current.value}"
            )


@dataclass(frozen=True, slots=True)
class CaptureStateSnapshot:
    state: CaptureState
    generation: CaptureGeneration | None
    observed_at: datetime
    privacy_mode: bool
    critical_dependencies_healthy: bool

    def __post_init__(self) -> None:
        require_aware(self.observed_at, "observed_at")
        if self.state in {CaptureState.STARTING, CaptureState.RECORDING, CaptureState.PAUSED}:
            if self.generation is None:
                raise ValueError("active capture states require a generation")
