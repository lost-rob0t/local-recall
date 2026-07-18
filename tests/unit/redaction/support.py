from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.domain.frames import OCRBlock, OCRResult, PixelFormat, RawFrame
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.redaction import PixelRegion


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
    width: int = 32,
    height: int = 2,
    pixels: bytes | None = None,
    frame_id: UUID | None = None,
    context: ContextMetadata | None = None,
) -> RawFrame:
    resolved = pixels or bytes(range(width)) * height
    return RawFrame(
        frame_id=frame_id or uuid4(),
        generation=CaptureGeneration(1),
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        width=width,
        height=height,
        stride=width,
        pixel_format=PixelFormat.GRAY8,
        pixels=resolved,
        metadata=context or metadata(("application", "synthetic")),
    )


def ocr(frame: RawFrame, *blocks: tuple[str, float, PixelRegion]) -> OCRResult:
    return OCRResult(
        frame_id=frame.frame_id,
        blocks=tuple(
            OCRBlock(
                block_id=uuid4(),
                frame_id=frame.frame_id,
                text=text,
                confidence=SourceConfidence(confidence),
                region=region,
            )
            for text, confidence, region in blocks
        ),
    )
