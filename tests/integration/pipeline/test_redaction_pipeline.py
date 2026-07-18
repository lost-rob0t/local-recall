from __future__ import annotations

import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.domain.frames import OCRBlock, OCRResult, RedactedRecord
from local_recall.domain.metadata import SourceConfidence
from local_recall.domain.redaction import PixelRegion
from local_recall.pipeline import (
    BoundedCapturePipeline,
    EncryptedStageItem,
    PipelineCancellationToken,
    PipelineStage,
    RedactedStageItem,
    SubmissionStatus,
)
from local_recall.ports.ocr import OCRRequest
from local_recall.redaction import (
    DeterministicRedactionPolicy,
    LocalOCRStageProcessor,
    PrePersistenceRedactionStageProcessor,
    decode_redacted_stage,
    encode_raw_frame,
)

from .support import (
    RecordingFaultSink,
    RecordingSink,
    gray_frame,
    metadata,
    recording_gate,
)


@dataclass
class SyntheticOCRProvider:
    text: str
    region: PixelRegion

    @property
    def provider_id(self) -> str:
        return "synthetic-local"

    async def recognize(self, request: OCRRequest) -> OCRResult:
        return OCRResult(
            frame_id=request.frame.frame_id,
            blocks=(
                OCRBlock(
                    block_id=uuid4(),
                    frame_id=request.frame.frame_id,
                    text=self.text,
                    confidence=SourceConfidence(0.99),
                    region=self.region,
                ),
            ),
        )


class InspectingEncryptionProcessor:
    def __init__(self) -> None:
        self.record: RedactedRecord | None = None
        self.serialized_frames: tuple[bytes, ...] = ()
        self.event = threading.Event()

    def process(
        self, item: RedactedStageItem, cancellation: PipelineCancellationToken
    ) -> EncryptedStageItem:
        assert not cancellation.cancelled
        self.serialized_frames = item.frames
        self.record = decode_redacted_stage(item)
        self.event.set()
        return EncryptedStageItem(
            record_id=item.record_id,
            generation=item.generation,
            configuration_revision=item.configuration_revision,
            deadline_monotonic_ns=item.deadline_monotonic_ns,
            frames=(b"synthetic-ciphertext",),
        )


def test_pipeline_persists_only_redacted_output_without_filesystem_plaintext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "password=" + "synthetic-passphrase"
    record_id = uuid4()
    frame = gray_frame(
        width=len(marker),
        height=1,
        pixels=marker.encode(),
        frame_id=record_id,
        context=metadata(
            ("application", "editor"),
            ("window.password", "synthetic-passphrase"),
        ),
    )
    raw_frames = tuple(bytearray(value) for value in encode_raw_frame(frame))
    filesystem_calls: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> object:
        del args, kwargs
        filesystem_calls.append("called")
        raise AssertionError("plaintext filesystem access is forbidden")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", forbidden)
    monkeypatch.setattr(tempfile, "mkstemp", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)

    gate, _ = recording_gate()
    encryption = InspectingEncryptionProcessor()
    sink = RecordingSink()
    fault_sink = RecordingFaultSink()
    pipeline = BoundedCapturePipeline(
        gate=gate,
        raw_processor=LocalOCRStageProcessor(
            SyntheticOCRProvider(marker, PixelRegion(0, 0, len(marker), 1))
        ),
        analysis_processor=PrePersistenceRedactionStageProcessor(DeterministicRedactionPolicy()),
        redaction_processor=encryption,
        sink=sink,
        fault_sink=fault_sink,
    )

    try:
        result = pipeline.submit_raw(record_id=record_id, frames=raw_frames)
        assert result.status is SubmissionStatus.ACCEPTED
        assert sink.event.wait(2)
        assert encryption.event.is_set()

        assert all(frame_bytes == bytearray(len(frame_bytes)) for frame_bytes in raw_frames)
        assert encryption.record is not None
        assert encryption.record.frame.ocr_text == ("password=[REDACTED]",)
        assert encryption.record.frame.pixels == bytes(len(marker))
        assert encryption.record.frame.metadata.get("window.password") is None
        assert marker.encode() not in b"".join(encryption.serialized_frames)
        assert marker not in repr(encryption.record)
        assert sink.items[0].frames == (b"synthetic-ciphertext",)
        assert fault_sink.events == []
        assert filesystem_calls == []
    finally:
        pipeline.close()


def test_redaction_failure_rejects_record_without_storage_or_content_leak() -> None:
    marker = "password=" + "failure-marker"
    record_id = uuid4()
    frame = gray_frame(
        width=4,
        height=1,
        pixels=b"abcd",
        frame_id=record_id,
    )
    raw_frames = tuple(bytearray(value) for value in encode_raw_frame(frame))
    gate, _ = recording_gate()
    sink = RecordingSink()
    fault_sink = RecordingFaultSink()
    pipeline = BoundedCapturePipeline(
        gate=gate,
        raw_processor=LocalOCRStageProcessor(SyntheticOCRProvider(marker, PixelRegion(3, 0, 4, 1))),
        analysis_processor=PrePersistenceRedactionStageProcessor(DeterministicRedactionPolicy()),
        redaction_processor=InspectingEncryptionProcessor(),
        sink=sink,
        fault_sink=fault_sink,
    )

    try:
        assert (
            pipeline.submit_raw(record_id=record_id, frames=raw_frames).status
            is SubmissionStatus.ACCEPTED
        )
        assert fault_sink.event.wait(2)

        assert sink.items == []
        assert fault_sink.events[0].record_id == record_id
        assert fault_sink.events[0].stage is PipelineStage.ANALYZED
        assert marker not in str(fault_sink.events[0])
        assert marker not in repr(fault_sink.events[0])
    finally:
        pipeline.close()
