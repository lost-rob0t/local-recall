from __future__ import annotations

import json
from typing import Any, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from local_recall.domain.lifecycle import CaptureGeneration

from .errors import PipelineProtocolError
from .models import (
    AnalyzedStageItem,
    EncryptedStageItem,
    PipelineItem,
    PipelineLimits,
    PipelineStage,
    RawStageItem,
    RedactedStageItem,
)

_PROTOCOL_VERSION = 1


class TransportHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)

    protocol_version: int = Field(gt=0)
    record_id: UUID
    generation: int = Field(gt=0)
    configuration_revision: str = Field(min_length=1, max_length=256)
    stage: PipelineStage
    deadline_monotonic_ns: int = Field(gt=0)
    frame_count: int = Field(ge=1)
    frame_sizes: tuple[int, ...]

    def validate_declared_frames(self) -> None:
        if self.protocol_version != _PROTOCOL_VERSION:
            raise PipelineProtocolError(
                "unsupported protocol version",
                record_id=self.record_id,
            )
        if self.frame_count != len(self.frame_sizes):
            raise PipelineProtocolError(
                "declared frame count is inconsistent",
                record_id=self.record_id,
            )
        if any(size < 0 for size in self.frame_sizes):
            raise PipelineProtocolError(
                "declared frame size is invalid",
                record_id=self.record_id,
            )


def encode_item(item: PipelineItem, limits: PipelineLimits) -> list[bytes]:
    frames = tuple(bytes(frame) for frame in item.frames)
    _validate_payload_limits(frames, limits, record_id=item.record_id)
    header = TransportHeader(
        protocol_version=_PROTOCOL_VERSION,
        record_id=item.record_id,
        generation=item.generation.value,
        configuration_revision=item.configuration_revision,
        stage=item.stage,
        deadline_monotonic_ns=item.deadline_monotonic_ns,
        frame_count=len(frames),
        frame_sizes=tuple(len(frame) for frame in frames),
    )
    encoded_header = json.dumps(
        header.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded_header) > limits.max_header_bytes:
        raise PipelineProtocolError(
            "transport header exceeds configured limit", record_id=item.record_id
        )
    return [encoded_header, *frames]


def decode_item(
    parts: list[bytes],
    *,
    expected_stage: PipelineStage,
    limits: PipelineLimits,
) -> PipelineItem:
    if len(parts) < 2:
        raise PipelineProtocolError("multipart message is incomplete")
    if len(parts) - 1 > limits.max_frames:
        raise PipelineProtocolError("multipart message has too many frames")
    encoded_header = parts[0]
    if len(encoded_header) > limits.max_header_bytes:
        raise PipelineProtocolError("transport header exceeds configured limit")

    raw_header_value: Any
    try:
        raw_header_value = json.loads(encoded_header)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PipelineProtocolError("transport header is not valid JSON") from exc
    if not isinstance(raw_header_value, dict):
        raise PipelineProtocolError("transport header must be an object")
    raw_header = cast(dict[str, object], raw_header_value)
    try:
        header = TransportHeader.model_validate(raw_header)
    except ValidationError as exc:
        record_id = _extract_record_id(raw_header)
        raise PipelineProtocolError(
            "transport header failed validation", record_id=record_id
        ) from exc

    header.validate_declared_frames()
    if header.stage is not expected_stage:
        raise PipelineProtocolError(
            "message arrived at the wrong stage", record_id=header.record_id
        )

    payload_frames = tuple(parts[1:])
    if header.frame_count != len(payload_frames):
        raise PipelineProtocolError("multipart frame count mismatch", record_id=header.record_id)
    actual_sizes = tuple(len(frame) for frame in payload_frames)
    if actual_sizes != header.frame_sizes:
        raise PipelineProtocolError("multipart frame size mismatch", record_id=header.record_id)
    _validate_payload_limits(payload_frames, limits, record_id=header.record_id)

    generation = CaptureGeneration(header.generation)
    if header.stage is PipelineStage.RAW:
        return RawStageItem(
            record_id=header.record_id,
            generation=generation,
            configuration_revision=header.configuration_revision,
            deadline_monotonic_ns=header.deadline_monotonic_ns,
            frames=tuple(bytearray(frame) for frame in payload_frames),
        )
    if header.stage is PipelineStage.ANALYZED:
        return AnalyzedStageItem(
            record_id=header.record_id,
            generation=generation,
            configuration_revision=header.configuration_revision,
            deadline_monotonic_ns=header.deadline_monotonic_ns,
            frames=payload_frames,
        )
    if header.stage is PipelineStage.REDACTED:
        return RedactedStageItem(
            record_id=header.record_id,
            generation=generation,
            configuration_revision=header.configuration_revision,
            deadline_monotonic_ns=header.deadline_monotonic_ns,
            frames=payload_frames,
        )
    return EncryptedStageItem(
        record_id=header.record_id,
        generation=generation,
        configuration_revision=header.configuration_revision,
        deadline_monotonic_ns=header.deadline_monotonic_ns,
        frames=payload_frames,
    )


def peek_record_and_generation(parts: list[bytes]) -> tuple[UUID | None, CaptureGeneration | None]:
    if not parts:
        return None, None
    try:
        raw_header_value: Any = json.loads(parts[0])
    except UnicodeDecodeError, json.JSONDecodeError:
        return None, None
    if not isinstance(raw_header_value, dict):
        return None, None
    raw_header = cast(dict[str, object], raw_header_value)
    record_id = _extract_record_id(raw_header)
    generation_value = raw_header.get("generation")
    if isinstance(generation_value, int) and generation_value > 0:
        return record_id, CaptureGeneration(generation_value)
    return record_id, None


def _validate_payload_limits(
    frames: tuple[bytes, ...], limits: PipelineLimits, *, record_id: UUID | None
) -> None:
    if not frames:
        raise PipelineProtocolError(
            "pipeline payload requires at least one frame", record_id=record_id
        )
    if len(frames) > limits.max_frames:
        raise PipelineProtocolError("pipeline payload has too many frames", record_id=record_id)
    if sum(len(frame) for frame in frames) > limits.max_payload_bytes:
        raise PipelineProtocolError(
            "pipeline payload exceeds configured limit", record_id=record_id
        )


def _extract_record_id(raw_header: dict[str, object]) -> UUID | None:
    value = raw_header.get("record_id")
    try:
        return UUID(str(value))
    except TypeError, ValueError:
        return None
