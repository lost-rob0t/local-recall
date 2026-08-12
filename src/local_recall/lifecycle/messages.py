from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from local_recall.config.manager import ConfigurationSnapshot
from local_recall.domain.lifecycle import (
    CaptureGeneration,
    CaptureState,
    CaptureStateSnapshot,
    TransitionReason,
)

from .gate import CaptureWorkPermit


class LifecycleFaultCode(StrEnum):
    UNSUPPORTED_SESSION = "unsupported_session"
    ENCRYPTION_UNAVAILABLE = "encryption_unavailable"
    POLICY_FAILURE = "policy_failure"
    PREFLIGHT_FAILURE = "preflight_failure"
    PREFLIGHT_TIMEOUT = "preflight_timeout"
    CANCELLATION_FAILURE = "cancellation_failure"
    QUIESCENCE_TIMEOUT = "quiescence_timeout"
    BUFFER_CLEAR_FAILURE = "buffer_clear_failure"
    AUDIT_FAILURE = "audit_failure"
    ACTOR_FAILURE = "actor_failure"
    SHUTDOWN_FAILURE = "shutdown_failure"


@dataclass(frozen=True, slots=True)
class LifecyclePreflightRequest:
    configuration: ConfigurationSnapshot
    generation: CaptureGeneration
    deadline_monotonic_ns: int
    cancellation: CaptureWorkPermit = field(repr=False)

    def __post_init__(self) -> None:
        if self.deadline_monotonic_ns <= 0:
            raise ValueError("preflight deadline must be positive")
        if self.cancellation.generation != self.generation:
            raise ValueError("preflight cancellation token generation mismatch")


@dataclass(frozen=True, slots=True)
class LifecyclePreflightResult:
    ready: bool
    fault_code: LifecycleFaultCode | None = None
    start_paused_reason: TransitionReason | None = None

    def __post_init__(self) -> None:
        if self.ready and self.fault_code is not None:
            raise ValueError("successful preflight cannot include a fault code")
        if not self.ready and self.fault_code is None:
            raise ValueError("failed preflight requires a fault code")
        if not self.ready and self.start_paused_reason is not None:
            raise ValueError("failed preflight cannot request a paused start")
        if self.start_paused_reason not in {
            None,
            TransitionReason.SESSION_LOCKED,
            TransitionReason.IDLE,
        }:
            raise ValueError("preflight paused start requires a session-safety reason")

    @classmethod
    def success(
        cls,
        *,
        start_paused_reason: TransitionReason | None = None,
    ) -> LifecyclePreflightResult:
        return cls(ready=True, start_paused_reason=start_paused_reason)

    @classmethod
    def failure(cls, fault_code: LifecycleFaultCode) -> LifecyclePreflightResult:
        return cls(ready=False, fault_code=fault_code)


@dataclass(frozen=True, slots=True)
class StartCapture:
    reason: TransitionReason = TransitionReason.USER_START


@dataclass(frozen=True, slots=True)
class PauseCapture:
    reason: TransitionReason = TransitionReason.USER_PAUSE


@dataclass(frozen=True, slots=True)
class ResumeCapture:
    reason: TransitionReason = TransitionReason.USER_RESUME


@dataclass(frozen=True, slots=True)
class SetAutomaticCaptureBlock:
    blocked: bool
    reason: TransitionReason

    def __post_init__(self) -> None:
        allowed = (
            {TransitionReason.SESSION_LOCKED, TransitionReason.IDLE}
            if self.blocked
            else {TransitionReason.SESSION_UNLOCKED, TransitionReason.ACTIVE}
        )
        if self.reason not in allowed:
            raise ValueError("automatic capture block reason does not match requested state")


@dataclass(frozen=True, slots=True)
class StopCapture:
    reason: TransitionReason = TransitionReason.USER_STOP


@dataclass(frozen=True, slots=True)
class FaultCapture:
    fault_code: LifecycleFaultCode
    reason: TransitionReason = TransitionReason.CRITICAL_FAULT


@dataclass(frozen=True, slots=True)
class GetLifecycleSnapshot:
    pass


@dataclass(frozen=True, slots=True)
class LifecycleCommandResult:
    accepted: bool
    changed: bool
    snapshot: CaptureStateSnapshot
    reason_code: str
    fault_code: LifecycleFaultCode | None = None


@dataclass(frozen=True, slots=True)
class LifecycleAuditEvent:
    previous: CaptureState
    current: CaptureState
    reason: TransitionReason
    generation: int
    configuration_revision: str | None
    occurred_at: datetime
    fault_code: LifecycleFaultCode | None = None
    event_type: str = "capture.lifecycle.transition"
    event_id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class RunLifecyclePreflight:
    configuration: ConfigurationSnapshot
    generation: CaptureGeneration
    deadline_monotonic_ns: int
    reason: TransitionReason


@dataclass(frozen=True, slots=True)
class CompleteLifecyclePreflight:
    generation: CaptureGeneration
    result: LifecyclePreflightResult
    reason: TransitionReason
