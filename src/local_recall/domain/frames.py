from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from ._validation import require_aware, require_nonempty
from .lifecycle import CaptureGeneration
from .metadata import ContextMetadata, SourceConfidence
from .redaction import PixelRegion, RedactionAllowlistDecision, RedactionFinding


class PixelFormat(StrEnum):
    RGBA8 = "rgba8"
    RGB8 = "rgb8"
    GRAY8 = "gray8"

    @property
    def bytes_per_pixel(self) -> int:
        return {PixelFormat.RGBA8: 4, PixelFormat.RGB8: 3, PixelFormat.GRAY8: 1}[self]


@dataclass(frozen=True, slots=True)
class CaptureRegion:
    x: int
    y: int
    width: int
    height: int

    def __post_init__(self) -> None:
        if self.width <= 0 or self.height <= 0:
            raise ValueError("capture region dimensions must be positive")


@dataclass(frozen=True, slots=True)
class MonitorGeometry:
    monitor_id: str
    x: int
    y: int
    width: int
    height: int
    scale_x: float = 1.0
    scale_y: float = 1.0

    def __post_init__(self) -> None:
        require_nonempty(self.monitor_id, "monitor_id")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("monitor dimensions must be positive")
        if not math.isfinite(self.scale_x) or not math.isfinite(self.scale_y):
            raise ValueError("monitor scale must be finite")
        if self.scale_x <= 0 or self.scale_y <= 0:
            raise ValueError("monitor scale must be positive")


@dataclass(frozen=True, slots=True)
class CaptureProvenance:
    backend_id: str
    backend_revision: str
    root_region: CaptureRegion
    region: CaptureRegion
    monitors: tuple[MonitorGeometry, ...]

    def __post_init__(self) -> None:
        require_nonempty(self.backend_id, "backend_id")
        require_nonempty(self.backend_revision, "backend_revision")


def _validate_frame(
    *,
    captured_at: datetime,
    width: int,
    height: int,
    stride: int,
    pixel_format: PixelFormat,
    pixels: bytes,
) -> None:
    require_aware(captured_at, "captured_at")
    if width <= 0 or height <= 0:
        raise ValueError("frame dimensions must be positive")
    minimum_stride = width * pixel_format.bytes_per_pixel
    if stride < minimum_stride:
        raise ValueError("frame stride is smaller than the pixel width")
    required_size = stride * height
    if len(pixels) != required_size:
        raise ValueError(f"pixel buffer must contain exactly {required_size} bytes")


@dataclass(frozen=True, slots=True, repr=False)
class RawFrame:
    frame_id: UUID
    generation: CaptureGeneration
    captured_at: datetime
    width: int
    height: int
    stride: int
    pixel_format: PixelFormat
    pixels: bytes = field(repr=False)
    metadata: ContextMetadata
    capture_provenance: CaptureProvenance | None = None

    def __post_init__(self) -> None:
        _validate_frame(
            captured_at=self.captured_at,
            width=self.width,
            height=self.height,
            stride=self.stride,
            pixel_format=self.pixel_format,
            pixels=self.pixels,
        )

    def __repr__(self) -> str:
        return (
            f"RawFrame(frame_id={self.frame_id!r}, generation={self.generation!r}, "
            f"captured_at={self.captured_at!r}, dimensions={self.width}x{self.height}, "
            f"pixel_format={self.pixel_format.value!r}, pixel_bytes={len(self.pixels)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class OCRBlock:
    block_id: UUID
    frame_id: UUID
    text: str = field(repr=False)
    confidence: SourceConfidence
    region: PixelRegion

    def __repr__(self) -> str:
        return (
            f"OCRBlock(block_id={self.block_id!r}, frame_id={self.frame_id!r}, "
            f"text_length={len(self.text)}, confidence={self.confidence!r}, "
            f"region={self.region!r})"
        )


@dataclass(frozen=True, slots=True)
class OCRResult:
    frame_id: UUID
    blocks: tuple[OCRBlock, ...]

    def __post_init__(self) -> None:
        if any(block.frame_id != self.frame_id for block in self.blocks):
            raise ValueError("all OCR blocks must belong to the same frame")


@dataclass(frozen=True, slots=True, repr=False)
class RedactedFrame:
    frame_id: UUID
    generation: CaptureGeneration
    captured_at: datetime
    width: int
    height: int
    stride: int
    pixel_format: PixelFormat
    pixels: bytes = field(repr=False)
    metadata: ContextMetadata
    ocr_text: tuple[str, ...] = field(repr=False)
    findings: tuple[RedactionFinding, ...]
    policy_revision: str
    allowlist_decisions: tuple[RedactionAllowlistDecision, ...] = ()

    def __post_init__(self) -> None:
        _validate_frame(
            captured_at=self.captured_at,
            width=self.width,
            height=self.height,
            stride=self.stride,
            pixel_format=self.pixel_format,
            pixels=self.pixels,
        )
        require_nonempty(self.policy_revision, "policy_revision")

    def __repr__(self) -> str:
        return (
            f"RedactedFrame(frame_id={self.frame_id!r}, generation={self.generation!r}, "
            f"captured_at={self.captured_at!r}, dimensions={self.width}x{self.height}, "
            f"pixel_format={self.pixel_format.value!r}, pixel_bytes={len(self.pixels)}, "
            f"ocr_blocks={len(self.ocr_text)}, findings={len(self.findings)}, "
            f"allowlist_decisions={len(self.allowlist_decisions)}, "
            f"policy_revision={self.policy_revision!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RedactedRecord:
    record_id: UUID
    frame: RedactedFrame
    created_at: datetime

    def __post_init__(self) -> None:
        require_aware(self.created_at, "created_at")

    def __repr__(self) -> str:
        return (
            f"RedactedRecord(record_id={self.record_id!r}, frame_id={self.frame.frame_id!r}, "
            f"created_at={self.created_at!r}, findings={len(self.frame.findings)})"
        )
