from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.domain.frames import PixelFormat, RawFrame
from local_recall.domain.lifecycle import CaptureGeneration, TransitionReason
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.lifecycle.gate import CaptureGate
from local_recall.pipeline import (
    AnalyzedStageItem,
    EncryptedStageItem,
    PipelineCancellationToken,
    PipelineFaultEvent,
    RawStageItem,
    RedactedStageItem,
)


def provenance() -> tuple[MetadataProvenance, ...]:
    return (
        MetadataProvenance(
            source_id="synthetic",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            confidence=SourceConfidence(1.0),
            adapter_revision="test-v1",
        ),
    )


def metadata(*fields: tuple[str, str | int | float | bool | None]) -> ContextMetadata:
    return ContextMetadata(
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        fields=tuple(ContextField(name, value, provenance()) for name, value in fields),
    )


def gray_frame(
    *,
    width: int,
    height: int,
    pixels: bytes,
    frame_id: UUID | None = None,
    context: ContextMetadata | None = None,
) -> RawFrame:
    return RawFrame(
        frame_id=frame_id or uuid4(),
        generation=CaptureGeneration(1),
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        width=width,
        height=height,
        stride=width,
        pixel_format=PixelFormat.GRAY8,
        pixels=pixels,
        metadata=context or metadata(("application", "synthetic")),
    )


def recording_gate() -> tuple[CaptureGate, CaptureGeneration]:
    gate = CaptureGate()
    gate.bind_owner()
    generation, _ = gate.begin_start(TransitionReason.USER_START, "config-v1")
    gate.mark_recording(generation, TransitionReason.USER_START)
    gate.release_owner()
    return gate, generation


class CopyRawProcessor:
    def process(
        self, item: RawStageItem, cancellation: PipelineCancellationToken
    ) -> AnalyzedStageItem:
        assert not cancellation.cancelled
        return AnalyzedStageItem(
            record_id=item.record_id,
            generation=item.generation,
            configuration_revision=item.configuration_revision,
            deadline_monotonic_ns=item.deadline_monotonic_ns,
            frames=tuple(bytes(frame) + b"-analyzed" for frame in item.frames),
        )


class CopyAnalysisProcessor:
    def process(
        self, item: AnalyzedStageItem, cancellation: PipelineCancellationToken
    ) -> RedactedStageItem:
        assert not cancellation.cancelled
        return RedactedStageItem(
            record_id=item.record_id,
            generation=item.generation,
            configuration_revision=item.configuration_revision,
            deadline_monotonic_ns=item.deadline_monotonic_ns,
            frames=tuple(frame + b"-redacted" for frame in item.frames),
        )


class CopyRedactionProcessor:
    def process(
        self, item: RedactedStageItem, cancellation: PipelineCancellationToken
    ) -> EncryptedStageItem:
        assert not cancellation.cancelled
        return EncryptedStageItem(
            record_id=item.record_id,
            generation=item.generation,
            configuration_revision=item.configuration_revision,
            deadline_monotonic_ns=item.deadline_monotonic_ns,
            frames=tuple(frame + b"-encrypted" for frame in item.frames),
        )


@dataclass
class RecordingSink:
    items: list[EncryptedStageItem] = field(default_factory=list[EncryptedStageItem])
    event: threading.Event = field(default_factory=threading.Event)

    def persist(self, item: EncryptedStageItem, cancellation: PipelineCancellationToken) -> None:
        if cancellation.cancelled:
            return
        self.items.append(item)
        self.event.set()


@dataclass
class RecordingFaultSink:
    events: list[PipelineFaultEvent] = field(default_factory=list[PipelineFaultEvent])
    event: threading.Event = field(default_factory=threading.Event)

    def emit(self, event: PipelineFaultEvent) -> None:
        self.events.append(event)
        self.event.set()


class BlockingRawProcessor:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()

    def process(
        self, item: RawStageItem, cancellation: PipelineCancellationToken
    ) -> AnalyzedStageItem:
        self.started.set()
        while not self.release.wait(0.01):
            if cancellation.cancelled:
                self.cancelled.set()
                break
        return AnalyzedStageItem(
            record_id=item.record_id,
            generation=item.generation,
            configuration_revision=item.configuration_revision,
            deadline_monotonic_ns=item.deadline_monotonic_ns,
            frames=(b"cancelled" if cancellation.cancelled else b"released",),
        )


class FailingRawProcessor:
    def __init__(self, marker: str) -> None:
        self.marker = marker

    def process(
        self, item: RawStageItem, cancellation: PipelineCancellationToken
    ) -> AnalyzedStageItem:
        del item, cancellation
        raise ValueError(self.marker)
