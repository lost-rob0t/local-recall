from __future__ import annotations

from local_recall.domain.lifecycle import TransitionReason
from local_recall.lifecycle.messages import LifecycleAuditEvent

from .models import AuditReasonCode
from .recorder import AuditRecorder


_REASON_MAP: dict[TransitionReason, AuditReasonCode] = {
    TransitionReason.USER_START: AuditReasonCode.USER_REQUEST,
    TransitionReason.STARTUP_OPT_IN: AuditReasonCode.STARTUP_OPT_IN,
    TransitionReason.USER_STOP: AuditReasonCode.USER_REQUEST,
    TransitionReason.USER_PAUSE: AuditReasonCode.CAPTURE_PAUSED,
    TransitionReason.USER_RESUME: AuditReasonCode.USER_REQUEST,
    TransitionReason.PRIVACY_ENABLED: AuditReasonCode.PRIVACY_MODE,
    TransitionReason.PRIVACY_DISABLED: AuditReasonCode.USER_REQUEST,
    TransitionReason.SESSION_LOCKED: AuditReasonCode.SESSION_LOCKED,
    TransitionReason.SESSION_UNLOCKED: AuditReasonCode.SESSION_UNLOCKED,
    TransitionReason.IDLE: AuditReasonCode.IDLE,
    TransitionReason.ACTIVE: AuditReasonCode.ACTIVE,
    TransitionReason.CRITICAL_FAULT: AuditReasonCode.CRITICAL_FAULT,
    TransitionReason.STARTUP_SAFE_DEFAULT: AuditReasonCode.STARTUP_SAFE_DEFAULT,
    TransitionReason.SHUTDOWN: AuditReasonCode.SHUTDOWN,
}


class LifecycleAuditAdapter:
    def __init__(self, recorder: AuditRecorder) -> None:
        self._recorder = recorder

    def emit(self, event: LifecycleAuditEvent) -> None:
        self._recorder.lifecycle_transition(
            reason=_REASON_MAP[event.reason],
            generation=event.generation,
            correlation_id=event.event_id,
            configuration_revision=event.configuration_revision,
            faulted=event.fault_code is not None,
        )
