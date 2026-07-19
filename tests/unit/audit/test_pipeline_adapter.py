from __future__ import annotations

from uuid import uuid4

from local_recall.audit import (
    AuditEvent,
    AuditReasonCode,
    AuditRecorder,
    PipelineAuditAdapter,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline.models import (
    PipelineFaultCode,
    PipelineFaultEvent,
    PipelineStage,
    SubmissionResult,
    SubmissionStatus,
)


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def test_pipeline_adapter_records_accepted_and_overloaded_submissions() -> None:
    sink = MemorySink()
    adapter = PipelineAuditAdapter(AuditRecorder(sink))
    generation = CaptureGeneration(3)

    adapter.record_submission(
        SubmissionResult(uuid4(), SubmissionStatus.ACCEPTED),
        generation,
        queue_depth=1,
    )
    adapter.record_submission(
        SubmissionResult(uuid4(), SubmissionStatus.DROPPED),
        generation,
        queue_depth=32,
    )

    assert [event.reason for event in sink.events] == [
        AuditReasonCode.POLICY_ALLOW,
        AuditReasonCode.OVERLOAD,
    ]
    assert sink.events[0].attributes["queue_depth"] == 1
    assert sink.events[1].attributes["queue_depth"] == 32


def test_pipeline_adapter_records_fixed_rejection_reason() -> None:
    sink = MemorySink()
    adapter = PipelineAuditAdapter(AuditRecorder(sink))
    record_id = uuid4()

    adapter.record_rejection(
        PipelineFaultEvent(
            record_id,
            PipelineStage.REDACTED,
            PipelineFaultCode.PROCESSOR_FAILURE,
        ),
        CaptureGeneration(4),
    )

    assert sink.events[-1].record_id == record_id
    assert sink.events[-1].reason is AuditReasonCode.REDACTION_FAILED
