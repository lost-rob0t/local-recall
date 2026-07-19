from __future__ import annotations

from local_recall.domain.lifecycle import CaptureGeneration, TransitionReason
from local_recall.lifecycle.messages import LifecycleAuditEvent
from local_recall.pipeline.models import (
    PipelineFaultCode,
    PipelineFaultEvent,
    PipelineStage,
    SubmissionResult,
    SubmissionStatus,
)

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
            previous_state=event.previous,
            current_state=event.current,
            configuration_revision=event.configuration_revision,
            faulted=event.fault_code is not None,
        )


class PipelineAuditAdapter:
    def __init__(self, recorder: AuditRecorder) -> None:
        self._recorder = recorder

    def record_submission(
        self,
        result: SubmissionResult,
        generation: CaptureGeneration,
        *,
        queue_depth: int,
    ) -> None:
        accepted = result.status is SubmissionStatus.ACCEPTED
        self._recorder.capture_decision(
            record_id=result.record_id,
            generation=generation.value,
            accepted=accepted,
            reason=(AuditReasonCode.POLICY_ALLOW if accepted else AuditReasonCode.OVERLOAD),
            attributes={"queue_depth": queue_depth},
        )

    def record_rejection(
        self,
        event: PipelineFaultEvent,
        generation: CaptureGeneration,
    ) -> None:
        self._recorder.record_rejected(
            record_id=event.record_id,
            generation=generation.value,
            reason=_pipeline_fault_reason(event),
        )


def _pipeline_fault_reason(event: PipelineFaultEvent) -> AuditReasonCode:
    if event.fault_code is PipelineFaultCode.PROTOCOL_FAILURE:
        return AuditReasonCode.INVALID_RECORD
    if event.fault_code in {
        PipelineFaultCode.TRANSPORT_FAILURE,
        PipelineFaultCode.PERSISTENCE_FAILURE,
    }:
        return AuditReasonCode.PERSISTENCE_FAILED
    if event.stage is PipelineStage.REDACTED:
        return AuditReasonCode.ENCRYPTION_UNAVAILABLE
    return AuditReasonCode.REDACTION_FAILED
