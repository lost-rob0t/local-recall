from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from local_recall.config.models import CaptureSettings
from local_recall.domain.lifecycle import CaptureGeneration


class PipelineStage(StrEnum):
    RAW = "raw"
    ANALYZED = "analyzed"
    REDACTED = "redacted"
    ENCRYPTED = "encrypted"


class PipelineOverloadPolicy(StrEnum):
    DROP_NEWEST = "drop-newest"
    COALESCE_LATEST = "coalesce-latest"


class SubmissionStatus(StrEnum):
    ACCEPTED = "accepted"
    DROPPED = "dropped"
    COALESCED = "coalesced"


class PipelineFaultCode(StrEnum):
    PROCESSOR_FAILURE = "processor_failure"
    PROTOCOL_FAILURE = "protocol_failure"
    TRANSPORT_FAILURE = "transport_failure"
    PERSISTENCE_FAILURE = "persistence_failure"


@dataclass(frozen=True, slots=True)
class PipelineLimits:
    raw_queue_items: int = 1
    stage_queue_items: int = 32
    overload_policy: PipelineOverloadPolicy = PipelineOverloadPolicy.DROP_NEWEST
    max_header_bytes: int = 16 * 1024
    max_frames: int = 8
    max_payload_bytes: int = 64 * 1024 * 1024
    receive_timeout_ms: int = 20
    send_timeout_ms: int = 10
    control_timeout_seconds: float = 1.0

    @classmethod
    def from_capture_settings(cls, settings: CaptureSettings) -> PipelineLimits:
        return cls(
            raw_queue_items=settings.raw_queue_items,
            stage_queue_items=settings.max_queue_items,
            overload_policy=PipelineOverloadPolicy(settings.overload_policy.value),
        )

    def __post_init__(self) -> None:
        if not 1 <= self.raw_queue_items <= 256:
            raise ValueError("raw_queue_items must be between 1 and 256")
        if not 1 <= self.stage_queue_items <= 256:
            raise ValueError("stage_queue_items must be between 1 and 256")
        if self.max_header_bytes <= 0:
            raise ValueError("max_header_bytes must be positive")
        if self.max_frames <= 0:
            raise ValueError("max_frames must be positive")
        if self.max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        if self.receive_timeout_ms <= 0 or self.send_timeout_ms < 0:
            raise ValueError("socket timeouts are invalid")
        if self.control_timeout_seconds <= 0:
            raise ValueError("control_timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    record_id: UUID
    status: SubmissionStatus
    replaced_record_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class PipelineFaultEvent:
    record_id: UUID
    stage: PipelineStage
    fault_code: PipelineFaultCode


@dataclass(frozen=True, slots=True, repr=False)
class RawStageItem:
    record_id: UUID
    generation: CaptureGeneration
    configuration_revision: str
    deadline_monotonic_ns: int
    frames: tuple[bytearray, ...] = field(repr=False)

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.RAW

    def destroy(self) -> None:
        for frame in self.frames:
            frame[:] = b"\x00" * len(frame)

    def __repr__(self) -> str:
        return _safe_repr(
            type(self).__name__, self.record_id, self.generation, self.stage, self.frames
        )


@dataclass(frozen=True, slots=True, repr=False)
class AnalyzedStageItem:
    record_id: UUID
    generation: CaptureGeneration
    configuration_revision: str
    deadline_monotonic_ns: int
    frames: tuple[bytes, ...] = field(repr=False)

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.ANALYZED

    def __repr__(self) -> str:
        return _safe_repr(
            type(self).__name__, self.record_id, self.generation, self.stage, self.frames
        )


@dataclass(frozen=True, slots=True, repr=False)
class RedactedStageItem:
    record_id: UUID
    generation: CaptureGeneration
    configuration_revision: str
    deadline_monotonic_ns: int
    frames: tuple[bytes, ...] = field(repr=False)

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.REDACTED

    def __repr__(self) -> str:
        return _safe_repr(
            type(self).__name__, self.record_id, self.generation, self.stage, self.frames
        )


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedStageItem:
    record_id: UUID
    generation: CaptureGeneration
    configuration_revision: str
    deadline_monotonic_ns: int
    frames: tuple[bytes, ...] = field(repr=False)

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.ENCRYPTED

    def __repr__(self) -> str:
        return _safe_repr(
            type(self).__name__, self.record_id, self.generation, self.stage, self.frames
        )


PipelineItem = RawStageItem | AnalyzedStageItem | RedactedStageItem | EncryptedStageItem


def _safe_repr(
    type_name: str,
    record_id: UUID,
    generation: CaptureGeneration,
    stage: PipelineStage,
    frames: tuple[bytes | bytearray, ...],
) -> str:
    sizes = tuple(len(frame) for frame in frames)
    return (
        f"{type_name}(record_id={record_id!r}, generation={generation!r}, "
        f"stage={stage.value!r}, frame_sizes={sizes!r})"
    )
