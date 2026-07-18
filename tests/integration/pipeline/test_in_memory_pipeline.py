from __future__ import annotations

import tempfile
import time
from pathlib import Path
from uuid import uuid4

import pytest
from local_recall.domain.lifecycle import TransitionReason
from local_recall.pipeline import BoundedCapturePipeline, SubmissionStatus
from tests.unit.pipeline.support import (
    BlockingRawProcessor,
    CopyAnalysisProcessor,
    CopyRawProcessor,
    CopyRedactionProcessor,
    FailingRawProcessor,
    RecordingFaultSink,
    RecordingSink,
    recording_gate,
)


def test_end_to_end_pipeline_never_uses_filesystem_backing(monkeypatch: pytest.MonkeyPatch) -> None:
    gate, _ = recording_gate()
    sink = RecordingSink()
    fault_sink = RecordingFaultSink()
    filesystem_calls: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        filesystem_calls.append("called")
        raise AssertionError("pipeline attempted filesystem-backed plaintext")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", forbidden)
    monkeypatch.setattr(tempfile, "mkstemp", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)

    pipeline = BoundedCapturePipeline(
        gate=gate,
        raw_processor=CopyRawProcessor(),
        analysis_processor=CopyAnalysisProcessor(),
        redaction_processor=CopyRedactionProcessor(),
        sink=sink,
        fault_sink=fault_sink,
    )
    payload = bytearray(b"screen-and-metadata")
    record_id = uuid4()

    try:
        result = pipeline.submit_raw(record_id=record_id, frames=(payload,))
        assert result.status is SubmissionStatus.ACCEPTED
        assert sink.event.wait(2)

        assert payload == bytearray(len(payload))
        assert sink.items[0].record_id == record_id
        assert sink.items[0].frames == (b"screen-and-metadata-analyzed-redacted-encrypted",)
        assert filesystem_calls == []
        assert fault_sink.events == []
        assert all(endpoint.startswith("inproc://") for endpoint in pipeline.endpoints)
    finally:
        pipeline.close()


def test_stop_cancels_in_flight_and_prevents_storage_write() -> None:
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
    )

    try:
        pipeline.submit_raw(record_id=uuid4(), frames=(bytearray(b"sensitive"),))
        assert blocker.started.wait(1)

        gate.bind_owner()
        stopped_generation, _ = gate.begin_stopping(TransitionReason.USER_STOP)
        gate.release_owner()
        assert stopped_generation == generation
        pipeline.cancel_queued(generation)
        pipeline.cancel_in_flight(generation)

        assert blocker.cancelled.wait(1)
        blocker.release.set()
        assert pipeline.wait_for_quiescence(generation, 2)
        pipeline.clear_volatile_buffers(generation)
        time.sleep(0.05)

        assert sink.items == []
        stats = pipeline.stats()
        assert stats.raw_credits == 0
        assert stats.analyzed_credits == 0
        assert stats.redacted_credits == 0
        assert stats.encrypted_credits == 0
    finally:
        blocker.release.set()
        pipeline.close()


def test_worker_fault_event_contains_record_id_but_not_captured_content() -> None:
    marker = "CAPTURED-CONTENT-MUST-NOT-LEAK"
    gate, _ = recording_gate()
    fault_sink = RecordingFaultSink()
    pipeline = BoundedCapturePipeline(
        gate=gate,
        raw_processor=FailingRawProcessor(marker),
        analysis_processor=CopyAnalysisProcessor(),
        redaction_processor=CopyRedactionProcessor(),
        sink=RecordingSink(),
        fault_sink=fault_sink,
    )
    record_id = uuid4()

    try:
        pipeline.submit_raw(record_id=record_id, frames=(bytearray(marker.encode()),))
        assert fault_sink.event.wait(2)

        event = fault_sink.events[0]
        assert event.record_id == record_id
        assert marker not in repr(event)
        assert marker not in str(event)
    finally:
        pipeline.close()
