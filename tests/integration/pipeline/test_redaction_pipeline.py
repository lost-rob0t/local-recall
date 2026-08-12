from __future__ import annotations

import asyncio
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.config import MetadataSettings
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.frames import OCRBlock, OCRResult, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata, SourceConfidence
from local_recall.domain.redaction import PixelRegion
from local_recall.metadata import (
    GenericXorgMetadataSource,
    QtileMetadataSource,
    QtileSnapshot,
    XorgWindowProperties,
)
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


class SyntheticXorgReader:
    def __init__(self, snapshot: XorgWindowProperties) -> None:
        self._snapshot = snapshot

    async def is_available(self) -> bool:
        return True

    async def active_window_id(self) -> int:
        return self._snapshot.window_id

    async def window_properties(
        self, window_id: int, *, include_title: bool
    ) -> XorgWindowProperties:
        assert window_id == self._snapshot.window_id
        assert include_title
        return self._snapshot


class SyntheticQtileReader:
    def __init__(self, snapshot: QtileSnapshot) -> None:
        self._snapshot = snapshot

    async def is_available(self) -> bool:
        return True

    async def snapshot(self, *, include_title: bool) -> QtileSnapshot:
        assert include_title
        return self._snapshot


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


def test_xorg_title_and_application_cross_redaction_before_persistence() -> None:
    marker = "password=" + "synthetic-metadata-secret"
    observed_at = datetime(2026, 8, 12, tzinfo=UTC)
    source = GenericXorgMetadataSource(
        MetadataSettings(window_titles_enabled=True),
        reader=SyntheticXorgReader(
            XorgWindowProperties(
                window_id=0x2A00007,
                application=marker,
                title=marker,
            )
        ),
        now=lambda: observed_at,
    )
    context = asyncio.run(
        source.collect(
            MetadataRequest(
                job_id=uuid4(),
                generation=CaptureGeneration(1),
                deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
            )
        )
    )
    _assert_metadata_redacted_before_persistence(
        context,
        marker,
        dropped_fields=("application", "window.title"),
    )


def test_qtile_sensitive_metadata_crosses_redaction_before_persistence() -> None:
    marker = "password=" + "synthetic-qtile-metadata-secret"
    observed_at = datetime(2026, 8, 12, tzinfo=UTC)
    source = QtileMetadataSource(
        MetadataSettings(window_titles_enabled=True),
        reader=SyntheticQtileReader(
            QtileSnapshot(
                window_id=0x2A00007,
                confirmed_window_id=0x2A00007,
                application=marker,
                title=marker,
                workspace=marker,
                confirmed_workspace=marker,
                layout="synthetic-layout",
                confirmed_layout="synthetic-layout",
                screen=1,
                confirmed_screen=1,
            )
        ),
        now=lambda: observed_at,
    )
    context = asyncio.run(
        source.collect(
            MetadataRequest(
                job_id=uuid4(),
                generation=CaptureGeneration(1),
                deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
            )
        )
    )
    _assert_metadata_redacted_before_persistence(
        context,
        marker,
        dropped_fields=("application", "window.title", "workspace"),
    )


def _assert_metadata_redacted_before_persistence(
    context: ContextMetadata,
    marker: str,
    *,
    dropped_fields: tuple[str, ...],
) -> None:
    record_id = uuid4()
    frame = gray_frame(
        width=4,
        height=1,
        pixels=b"safe",
        frame_id=record_id,
        context=context,
    )
    raw_frames = tuple(bytearray(value) for value in encode_raw_frame(frame))
    gate, _ = recording_gate()
    encryption = InspectingEncryptionProcessor()
    sink = RecordingSink()
    pipeline = BoundedCapturePipeline(
        gate=gate,
        raw_processor=LocalOCRStageProcessor(SyntheticOCRProvider("safe", PixelRegion(0, 0, 4, 1))),
        analysis_processor=PrePersistenceRedactionStageProcessor(DeterministicRedactionPolicy()),
        redaction_processor=encryption,
        sink=sink,
        fault_sink=RecordingFaultSink(),
    )

    try:
        assert (
            pipeline.submit_raw(record_id=record_id, frames=raw_frames).status
            is SubmissionStatus.ACCEPTED
        )
        assert sink.event.wait(2)
        assert encryption.record is not None
        for field_name in dropped_fields:
            assert encryption.record.frame.metadata.get(field_name) is None
        assert encryption.record.frame.metadata.get("window.id") == 0x2A00007
        assert marker not in repr(encryption.record)
        assert sink.items[0].frames == (b"synthetic-ciphertext",)
    finally:
        pipeline.close()
