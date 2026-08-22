from __future__ import annotations

from uuid import uuid4

from local_recall.pipeline import (
    BoundedCapturePipeline,
    PipelineLimits,
    PipelineOverloadPolicy,
    SubmissionStatus,
)

from .support import (
    BlockingRawProcessor,
    CopyAnalysisProcessor,
    CopyRedactionProcessor,
    RecordingFaultSink,
    RecordingSink,
    ids,
    recording_gate,
    wait_until,
)


def test_drop_newest_overload_never_exceeds_raw_credit() -> None:
    gate, generation = recording_gate()
    blocker = BlockingRawProcessor()
    sink = RecordingSink()
    pipeline = BoundedCapturePipeline(
        gate=gate,
        raw_processor=blocker,
        analysis_processor=CopyAnalysisProcessor(),
        redaction_processor=CopyRedactionProcessor(),
        sink=sink,
        fault_sink=RecordingFaultSink(),
        limits=PipelineLimits(
            raw_queue_items=1, overload_policy=PipelineOverloadPolicy.DROP_NEWEST
        ),
    )
    first = bytearray(b"first")
    second = bytearray(b"second")
    first_id = uuid4()

    try:
        assert (
            pipeline.submit_raw(
                record_id=first_id,
                frames=(first,),
                expected_generation=generation,
            ).status
            is SubmissionStatus.ACCEPTED
        )
        assert blocker.started.wait(1)
        result = pipeline.submit_raw(
            record_id=uuid4(),
            frames=(second,),
            expected_generation=generation,
        )

        assert result.status is SubmissionStatus.DROPPED
        assert second == bytearray(len(second))
        assert pipeline.stats().raw_credits == 1

        blocker.release.set()
        assert sink.event.wait(2)
        assert ids(sink.items) == [first_id]
    finally:
        blocker.release.set()
        pipeline.close()


def test_coalesce_latest_keeps_only_one_pending_raw_item() -> None:
    gate, generation = recording_gate()
    blocker = BlockingRawProcessor()
    sink = RecordingSink()
    pipeline = BoundedCapturePipeline(
        gate=gate,
        raw_processor=blocker,
        analysis_processor=CopyAnalysisProcessor(),
        redaction_processor=CopyRedactionProcessor(),
        sink=sink,
        fault_sink=RecordingFaultSink(),
        limits=PipelineLimits(
            raw_queue_items=1,
            overload_policy=PipelineOverloadPolicy.COALESCE_LATEST,
        ),
    )
    first_id, second_id, third_id = uuid4(), uuid4(), uuid4()
    second = bytearray(b"second")
    third = bytearray(b"third")

    try:
        assert (
            pipeline.submit_raw(
                record_id=first_id,
                frames=(bytearray(b"first"),),
                expected_generation=generation,
            ).status
            is SubmissionStatus.ACCEPTED
        )
        assert blocker.started.wait(1)
        assert (
            pipeline.submit_raw(
                record_id=second_id,
                frames=(second,),
                expected_generation=generation,
            ).status
            is SubmissionStatus.COALESCED
        )
        replacement = pipeline.submit_raw(
            record_id=third_id,
            frames=(third,),
            expected_generation=generation,
        )

        assert replacement.status is SubmissionStatus.COALESCED
        assert replacement.replaced_record_id == second_id
        assert second == bytearray(len(second))
        assert pipeline.stats().coalesced

        blocker.release.set()
        wait_until(lambda: pipeline.stats().raw_credits == 0)
        assert pipeline.flush_coalesced() is not None
        wait_until(lambda: len(sink.items) == 2)
        assert ids(sink.items) == [first_id, third_id]
        assert third == bytearray(len(third))
    finally:
        blocker.release.set()
        pipeline.close()
