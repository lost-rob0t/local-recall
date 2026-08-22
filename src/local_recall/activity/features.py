from __future__ import annotations

import math

from local_recall.capture.adaptive import perceptual_dhash_rgb8
from local_recall.domain.frames import PixelFormat, RedactedRecord
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import EmbeddingRequest, ModelCapability
from local_recall.ports.providers import EmbeddingProvider

from .clustering import ActivityRecordFeatures

_MAX_RECORDS = 512
_MAX_SEMANTIC_INPUT_BYTES = 16_384


class ActivityFeatureFailure(RuntimeError):
    """Sanitized failure while deriving activity-clustering features."""


class ActivityFeatureExtractor:
    __slots__ = ("_provider",)

    def __init__(self, provider: EmbeddingProvider) -> None:
        self._provider = provider

    def __repr__(self) -> str:
        return "ActivityFeatureExtractor(provider=redacted)"

    async def extract(
        self,
        records: tuple[RedactedRecord, ...],
    ) -> tuple[ActivityRecordFeatures, ...]:
        if not records:
            return ()
        if len(records) > _MAX_RECORDS:
            raise ActivityFeatureFailure("activity feature batch exceeds record limit")

        capabilities = await self._provider.capabilities()
        if capabilities.location is not ProviderLocation.LOCAL:
            raise ActivityFeatureFailure("local embedding provider required")
        if not capabilities.available:
            raise ActivityFeatureFailure("local embedding provider unavailable")
        if ModelCapability.EMBEDDING not in capabilities.capabilities:
            raise ActivityFeatureFailure("embedding capability required")
        if not capabilities.accepts(PrivacyClass.REDACTED_CONTENT):
            raise ActivityFeatureFailure("embedding provider rejects redacted content")

        semantic_inputs: list[str] = []
        semantic_positions: list[int] = []
        prepared: list[tuple[str | None, str | None, int]] = []
        total_input_bytes = 0

        for position, record in enumerate(records):
            frame = record.frame
            if frame.pixel_format is not PixelFormat.RGB8:
                raise ActivityFeatureFailure("activity fingerprint requires RGB8 redacted frame")
            try:
                fingerprint = perceptual_dhash_rgb8(
                    frame.pixels,
                    width=frame.width,
                    height=frame.height,
                    stride=frame.stride,
                )
            except ValueError as exc:
                raise ActivityFeatureFailure(
                    "invalid redacted frame for activity fingerprint"
                ) from exc

            application = _metadata_text(record, "application")
            workspace = _metadata_text(record, "workspace")
            prepared.append((application, workspace, fingerprint))

            semantic_input = _semantic_input(record, application=application, workspace=workspace)
            if semantic_input is None:
                continue
            input_bytes = len(semantic_input.encode("utf-8"))
            if input_bytes > _MAX_SEMANTIC_INPUT_BYTES:
                raise ActivityFeatureFailure("activity semantic input exceeds per-record limit")
            total_input_bytes += input_bytes
            semantic_positions.append(position)
            semantic_inputs.append(semantic_input)

        vectors_by_position: dict[int, tuple[float, ...]] = {}
        if semantic_inputs:
            if total_input_bytes > capabilities.max_input_bytes:
                raise ActivityFeatureFailure("activity semantic batch exceeds provider input limit")
            response = await self._provider.embed(
                EmbeddingRequest(
                    inputs=tuple(semantic_inputs),
                    privacy_class=PrivacyClass.REDACTED_CONTENT,
                )
            )
            if response.provider_id != capabilities.provider_id:
                raise ActivityFeatureFailure("embedding provider identity mismatch")
            if len(response.vectors) != len(semantic_positions):
                raise ActivityFeatureFailure("embedding response count mismatch")
            for position, vector in zip(semantic_positions, response.vectors, strict=True):
                if any(not math.isfinite(value) for value in vector):
                    raise ActivityFeatureFailure("embedding response contains non-finite values")
                vectors_by_position[position] = vector

        return tuple(
            ActivityRecordFeatures(
                record_id=record.record_id,
                captured_at=record.frame.captured_at,
                policy_revision=record.frame.policy_revision,
                application=prepared[position][0],
                workspace=prepared[position][1],
                perceptual_hash=prepared[position][2],
                semantic_vector=vectors_by_position.get(position),
            )
            for position, record in enumerate(records)
        )


def _metadata_text(record: RedactedRecord, name: str) -> str | None:
    value = record.frame.metadata.get(name)
    return value if isinstance(value, str) and value else None


def _semantic_input(
    record: RedactedRecord,
    *,
    application: str | None,
    workspace: str | None,
) -> str | None:
    parts = [item for item in record.frame.ocr_text if item]
    if application is not None:
        parts.append(f"application:{application}")
    if workspace is not None:
        parts.append(f"workspace:{workspace}")
    if not parts:
        return None
    return "\n".join(parts)
