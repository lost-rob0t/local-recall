from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from local_recall.capture.xorg import XorgCaptureBackend, XorgMonitor, XorgSnapshot
from local_recall.domain import (
    ApprovedCaptureRequest,
    CaptureDecision,
    CaptureIntent,
    ContextMetadata,
    PixelFormat,
    TransitionReason,
)
from local_recall.lifecycle import StaleCaptureGeneration
from local_recall.pipeline import BoundedCapturePipeline, SubmissionStatus
from local_recall.redaction import encode_raw_frame

from .support import (
    CopyAnalysisProcessor,
    CopyRawProcessor,
    CopyRedactionProcessor,
    RecordingFaultSink,
    RecordingSink,
    recording_gate,
)

NOW = datetime(2026, 8, 22, tzinfo=UTC)


class SyntheticXorgReader:
    async def capture_root(self, *, deadline_monotonic_ns: int) -> XorgSnapshot:
        assert deadline_monotonic_ns == 2_000_000_000
        return XorgSnapshot(
            captured_at=NOW,
            root_x=0,
            root_y=0,
            width=2,
            height=1,
            stride=6,
            pixel_format=PixelFormat.RGB8,
            pixels=b"\x01\x02\x03\x04\x05\x06",
            monitors=(XorgMonitor("screen-0", 0, 0, 2, 1),),
            backend_revision="synthetic-xorg-v1",
        )


def _approved_request(generation: object) -> ApprovedCaptureRequest:
    from local_recall.domain import CaptureGeneration

    if not isinstance(generation, CaptureGeneration):
        raise TypeError("capture generation required")
    intent = CaptureIntent(
        job_id=uuid4(),
        generation=generation,
        requested_at=NOW,
        deadline_monotonic_ns=2_000_000_000,
        configuration_revision="config-v1",
    )
    return ApprovedCaptureRequest.from_decision(
        intent=intent,
        metadata=ContextMetadata(observed_at=NOW, fields=()),
        decision=CaptureDecision.allow(
            policy_revision="policy-v1",
            allowed_metadata_fields=frozenset(),
        ),
    )


def _pipeline(
    gate: object, sink: RecordingSink, faults: RecordingFaultSink
) -> BoundedCapturePipeline:
    from local_recall.lifecycle import CaptureGate

    if not isinstance(gate, CaptureGate):
        raise TypeError("capture gate required")
    return BoundedCapturePipeline(
        gate=gate,
        raw_processor=CopyRawProcessor(),
        analysis_processor=CopyAnalysisProcessor(),
        redaction_processor=CopyRedactionProcessor(),
        sink=sink,
        fault_sink=faults,
    )


def test_approved_xorg_capture_enters_bounded_in_memory_redaction_pipeline() -> None:
    gate, generation = recording_gate()
    backend = XorgCaptureBackend(reader=SyntheticXorgReader(), monotonic_ns=lambda: 1)
    frame = asyncio.run(backend.capture(_approved_request(generation)))
    raw_frames = tuple(bytearray(value) for value in encode_raw_frame(frame))
    sink = RecordingSink()
    faults = RecordingFaultSink()
    pipeline = _pipeline(gate, sink, faults)

    try:
        result = pipeline.submit_raw(
            record_id=frame.frame_id,
            frames=raw_frames,
            expected_generation=frame.generation,
        )
        assert result.status is SubmissionStatus.ACCEPTED
        assert sink.event.wait(2)
        assert len(sink.items) == 1
        assert sink.items[0].generation == generation
        assert sink.items[0].frames[0].endswith(b"-analyzed-redacted-encrypted")
        assert faults.events == []
    finally:
        pipeline.close()


def test_late_xorg_frame_cannot_be_relabelled_after_generation_invalidation() -> None:
    gate, generation = recording_gate()
    backend = XorgCaptureBackend(reader=SyntheticXorgReader(), monotonic_ns=lambda: 1)
    frame = asyncio.run(backend.capture(_approved_request(generation)))
    raw_frames = tuple(bytearray(value) for value in encode_raw_frame(frame))

    gate.bind_owner()
    gate.invalidate_and_pause(TransitionReason.SESSION_LOCKED)
    gate.resume(TransitionReason.SESSION_UNLOCKED)
    gate.release_owner()

    sink = RecordingSink()
    faults = RecordingFaultSink()
    pipeline = _pipeline(gate, sink, faults)
    try:
        try:
            pipeline.submit_raw(
                record_id=frame.frame_id,
                frames=raw_frames,
                expected_generation=frame.generation,
            )
        except StaleCaptureGeneration:
            pass
        else:
            raise AssertionError("stale captured frame was relabelled to the current generation")

        assert all(value == bytearray(len(value)) for value in raw_frames)
        assert sink.items == []
        assert faults.events == []
    finally:
        pipeline.close()
