from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from local_recall.domain.frames import (
    OCRBlock,
    OCRResult,
    PixelFormat,
    RawFrame,
    RedactedFrame,
    RedactedRecord,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.redaction import (
    PixelRegion,
    RedactionAction,
    RedactionAllowlistDecision,
    RedactionFinding,
    RedactionKind,
    RedactionReason,
    RedactionTarget,
    TextSpan,
)
from local_recall.pipeline.models import (
    AnalyzedStageItem,
    RawStageItem,
    RedactedStageItem,
)

from .errors import RedactionFailure, RedactionFailureCode

_CODEC_VERSION = 1


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)


class _ProvenanceDTO(_FrozenModel):
    source_id: str
    observed_at: datetime
    confidence: float = Field(ge=0.0, le=1.0)
    adapter_revision: str | None = None


class _ContextFieldDTO(_FrozenModel):
    name: str
    value: str | int | float | bool | None
    provenance: tuple[_ProvenanceDTO, ...]


class _MetadataDTO(_FrozenModel):
    observed_at: datetime
    fields: tuple[_ContextFieldDTO, ...]


class _FrameDTO(_FrozenModel):
    frame_id: UUID
    generation: int = Field(gt=0)
    captured_at: datetime
    width: int = Field(gt=0)
    height: int = Field(gt=0)
    stride: int = Field(gt=0)
    pixel_format: PixelFormat
    metadata: _MetadataDTO


class _OCRBlockDTO(_FrozenModel):
    block_id: UUID
    frame_id: UUID
    text: str
    confidence: float = Field(ge=0.0, le=1.0)
    region: tuple[int, int, int, int]


class _FindingDTO(_FrozenModel):
    finding_id: UUID
    target: RedactionTarget
    kind: RedactionKind
    reason: RedactionReason
    action: RedactionAction
    detector_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    text_span: tuple[int, int] | None = None
    pixel_region: tuple[int, int, int, int] | None = None
    metadata_field: str | None = None


class _AllowlistDecisionDTO(_FrozenModel):
    decision_id: UUID
    detector_id: str
    allowlist_id: str
    target: RedactionTarget
    value_digest: str
    metadata_field: str | None = None


class _RawHeader(_FrozenModel):
    codec_version: int
    frame: _FrameDTO


class _AnalyzedHeader(_FrozenModel):
    codec_version: int
    frame: _FrameDTO
    blocks: tuple[_OCRBlockDTO, ...]


class _RedactedHeader(_FrozenModel):
    codec_version: int
    record_id: UUID
    created_at: datetime
    frame: _FrameDTO
    ocr_text: tuple[str, ...]
    findings: tuple[_FindingDTO, ...]
    policy_revision: str
    allowlist_decisions: tuple[_AllowlistDecisionDTO, ...]


@dataclass(frozen=True, slots=True)
class AnalyzedCapture:
    frame: RawFrame
    ocr: OCRResult


def encode_raw_frame(frame: RawFrame) -> tuple[bytes, bytes]:
    header = _RawHeader(codec_version=_CODEC_VERSION, frame=_frame_to_dto(frame))
    return _encode_header(header), frame.pixels


def decode_raw_stage(item: RawStageItem) -> RawFrame:
    header_bytes, pixels = _require_two_frames(item.record_id, item.frames)
    header = _decode_header(item.record_id, header_bytes, _RawHeader)
    _validate_version(item.record_id, header.codec_version)
    frame = _dto_to_raw_frame(header.frame, pixels)
    _validate_stage_identity(item.record_id, item.generation, frame)
    return frame


def encode_analyzed_stage(
    source: RawStageItem,
    frame: RawFrame,
    ocr: OCRResult,
) -> AnalyzedStageItem:
    _validate_stage_identity(source.record_id, source.generation, frame)
    if ocr.frame_id != frame.frame_id:
        raise RedactionFailure(source.record_id, RedactionFailureCode.FRAME_MISMATCH)
    header = _AnalyzedHeader(
        codec_version=_CODEC_VERSION,
        frame=_frame_to_dto(frame),
        blocks=tuple(_ocr_block_to_dto(block) for block in ocr.blocks),
    )
    return AnalyzedStageItem(
        record_id=source.record_id,
        generation=source.generation,
        configuration_revision=source.configuration_revision,
        deadline_monotonic_ns=source.deadline_monotonic_ns,
        frames=(_encode_header(header), frame.pixels),
    )


def decode_analyzed_stage(item: AnalyzedStageItem) -> AnalyzedCapture:
    header_bytes, pixels = _require_two_frames(item.record_id, item.frames)
    header = _decode_header(item.record_id, header_bytes, _AnalyzedHeader)
    _validate_version(item.record_id, header.codec_version)
    frame = _dto_to_raw_frame(header.frame, pixels)
    _validate_stage_identity(item.record_id, item.generation, frame)
    blocks = tuple(_dto_to_ocr_block(block) for block in header.blocks)
    return AnalyzedCapture(frame=frame, ocr=OCRResult(frame.frame_id, blocks))


def encode_redacted_stage(
    source: AnalyzedStageItem,
    record: RedactedRecord,
) -> RedactedStageItem:
    frame = record.frame
    _validate_stage_identity(source.record_id, source.generation, frame)
    if record.record_id != source.record_id:
        raise RedactionFailure(source.record_id, RedactionFailureCode.FRAME_MISMATCH)
    header = _RedactedHeader(
        codec_version=_CODEC_VERSION,
        record_id=record.record_id,
        created_at=record.created_at,
        frame=_redacted_frame_to_dto(frame),
        ocr_text=frame.ocr_text,
        findings=tuple(_finding_to_dto(item) for item in frame.findings),
        policy_revision=frame.policy_revision,
        allowlist_decisions=tuple(_allowlist_to_dto(item) for item in frame.allowlist_decisions),
    )
    return RedactedStageItem(
        record_id=source.record_id,
        generation=source.generation,
        configuration_revision=source.configuration_revision,
        deadline_monotonic_ns=source.deadline_monotonic_ns,
        frames=(_encode_header(header), frame.pixels),
    )


def decode_redacted_stage(item: RedactedStageItem) -> RedactedRecord:
    header_bytes, pixels = _require_two_frames(item.record_id, item.frames)
    header = _decode_header(item.record_id, header_bytes, _RedactedHeader)
    _validate_version(item.record_id, header.codec_version)
    if header.record_id != item.record_id:
        raise RedactionFailure(item.record_id, RedactionFailureCode.FRAME_MISMATCH)
    base = _dto_to_raw_frame(header.frame, pixels)
    _validate_stage_identity(item.record_id, item.generation, base)
    redacted = RedactedFrame(
        frame_id=base.frame_id,
        generation=base.generation,
        captured_at=base.captured_at,
        width=base.width,
        height=base.height,
        stride=base.stride,
        pixel_format=base.pixel_format,
        pixels=base.pixels,
        metadata=base.metadata,
        ocr_text=header.ocr_text,
        findings=tuple(_dto_to_finding(value) for value in header.findings),
        policy_revision=header.policy_revision,
        allowlist_decisions=tuple(_dto_to_allowlist(value) for value in header.allowlist_decisions),
    )
    return RedactedRecord(header.record_id, redacted, header.created_at)


def _frame_to_dto(frame: RawFrame) -> _FrameDTO:
    return _FrameDTO(
        frame_id=frame.frame_id,
        generation=frame.generation.value,
        captured_at=frame.captured_at,
        width=frame.width,
        height=frame.height,
        stride=frame.stride,
        pixel_format=frame.pixel_format,
        metadata=_metadata_to_dto(frame.metadata),
    )


def _redacted_frame_to_dto(frame: RedactedFrame) -> _FrameDTO:
    return _FrameDTO(
        frame_id=frame.frame_id,
        generation=frame.generation.value,
        captured_at=frame.captured_at,
        width=frame.width,
        height=frame.height,
        stride=frame.stride,
        pixel_format=frame.pixel_format,
        metadata=_metadata_to_dto(frame.metadata),
    )


def _metadata_to_dto(metadata: ContextMetadata) -> _MetadataDTO:
    return _MetadataDTO(
        observed_at=metadata.observed_at,
        fields=tuple(
            _ContextFieldDTO(
                name=field.name,
                value=field.value,
                provenance=tuple(
                    _ProvenanceDTO(
                        source_id=item.source_id,
                        observed_at=item.observed_at,
                        confidence=item.confidence.value,
                        adapter_revision=item.adapter_revision,
                    )
                    for item in field.provenance
                ),
            )
            for field in metadata.fields
        ),
    )


def _dto_to_metadata(metadata: _MetadataDTO) -> ContextMetadata:
    return ContextMetadata(
        observed_at=metadata.observed_at,
        fields=tuple(
            ContextField(
                name=field.name,
                value=field.value,
                provenance=tuple(
                    MetadataProvenance(
                        source_id=item.source_id,
                        observed_at=item.observed_at,
                        confidence=SourceConfidence(item.confidence),
                        adapter_revision=item.adapter_revision,
                    )
                    for item in field.provenance
                ),
            )
            for field in metadata.fields
        ),
    )


def _dto_to_raw_frame(frame: _FrameDTO, pixels: bytes | bytearray) -> RawFrame:
    return RawFrame(
        frame_id=frame.frame_id,
        generation=CaptureGeneration(frame.generation),
        captured_at=frame.captured_at,
        width=frame.width,
        height=frame.height,
        stride=frame.stride,
        pixel_format=frame.pixel_format,
        pixels=bytes(pixels),
        metadata=_dto_to_metadata(frame.metadata),
    )


def _ocr_block_to_dto(block: OCRBlock) -> _OCRBlockDTO:
    return _OCRBlockDTO(
        block_id=block.block_id,
        frame_id=block.frame_id,
        text=block.text,
        confidence=block.confidence.value,
        region=(block.region.x, block.region.y, block.region.width, block.region.height),
    )


def _dto_to_ocr_block(block: _OCRBlockDTO) -> OCRBlock:
    return OCRBlock(
        block_id=block.block_id,
        frame_id=block.frame_id,
        text=block.text,
        confidence=SourceConfidence(block.confidence),
        region=PixelRegion(*block.region),
    )


def _finding_to_dto(item: RedactionFinding) -> _FindingDTO:
    return _FindingDTO(
        finding_id=item.finding_id,
        target=item.target,
        kind=item.kind,
        reason=item.reason,
        action=item.action,
        detector_id=item.detector_id,
        confidence=item.confidence.value,
        text_span=(item.text_span.start, item.text_span.end) if item.text_span else None,
        pixel_region=(
            item.pixel_region.x,
            item.pixel_region.y,
            item.pixel_region.width,
            item.pixel_region.height,
        )
        if item.pixel_region
        else None,
        metadata_field=item.metadata_field,
    )


def _dto_to_finding(item: _FindingDTO) -> RedactionFinding:
    return RedactionFinding(
        finding_id=item.finding_id,
        target=item.target,
        kind=item.kind,
        reason=item.reason,
        action=item.action,
        detector_id=item.detector_id,
        confidence=SourceConfidence(item.confidence),
        text_span=TextSpan(*item.text_span) if item.text_span else None,
        pixel_region=PixelRegion(*item.pixel_region) if item.pixel_region else None,
        metadata_field=item.metadata_field,
    )


def _allowlist_to_dto(item: RedactionAllowlistDecision) -> _AllowlistDecisionDTO:
    return _AllowlistDecisionDTO(
        decision_id=item.decision_id,
        detector_id=item.detector_id,
        allowlist_id=item.allowlist_id,
        target=item.target,
        value_digest=item.value_digest,
        metadata_field=item.metadata_field,
    )


def _dto_to_allowlist(item: _AllowlistDecisionDTO) -> RedactionAllowlistDecision:
    return RedactionAllowlistDecision(
        decision_id=item.decision_id,
        detector_id=item.detector_id,
        allowlist_id=item.allowlist_id,
        target=item.target,
        value_digest=item.value_digest,
        metadata_field=item.metadata_field,
    )


def _encode_header(header: BaseModel) -> bytes:
    return json.dumps(header.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _decode_header[T: BaseModel](record_id: UUID, payload: bytes, model: type[T]) -> T:
    try:
        raw: Any = json.loads(payload)
        if not isinstance(raw, dict):
            raise ValueError("header must be an object")
        return model.model_validate(cast(dict[str, object], raw))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise RedactionFailure(record_id, RedactionFailureCode.CODEC_FAILURE) from exc


def _require_two_frames(
    record_id: UUID, frames: tuple[bytes | bytearray, ...]
) -> tuple[bytes, bytes | bytearray]:
    if len(frames) != 2:
        raise RedactionFailure(record_id, RedactionFailureCode.CODEC_FAILURE)
    return bytes(frames[0]), frames[1]


def _validate_version(record_id: UUID, version: int) -> None:
    if version != _CODEC_VERSION:
        raise RedactionFailure(record_id, RedactionFailureCode.CODEC_FAILURE)


def _validate_stage_identity(
    record_id: UUID, generation: CaptureGeneration, frame: RawFrame | RedactedFrame
) -> None:
    if frame.frame_id != record_id or frame.generation != generation:
        raise RedactionFailure(record_id, RedactionFailureCode.FRAME_MISMATCH)
