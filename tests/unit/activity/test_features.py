from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import pytest

from local_recall.activity.features import (
    ActivityFeatureExtractor,
    ActivityFeatureFailure,
)
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextField, ContextMetadata
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
    ModelCapability,
    ProviderCapabilities,
)


class Embeddings:
    def __init__(self, *, location: ProviderLocation = ProviderLocation.LOCAL) -> None:
        self.location = location
        self.requests: list[EmbeddingRequest] = []

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="synthetic-embedding",
            location=self.location,
            capabilities=frozenset({ModelCapability.EMBEDDING}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=65_536,
            supports_vision=False,
        )

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        self.requests.append(request)
        return EmbeddingResponse(
            provider_id="synthetic-embedding",
            model_id="embed-v1",
            vectors=tuple((1.0, float(index)) for index, _ in enumerate(request.inputs)),
        )


def _record(value: int, text: str, *, application: str = "emacs") -> RedactedRecord:
    captured_at = datetime(2026, 8, 22, 12, value, tzinfo=UTC)
    metadata = ContextMetadata(
        observed_at=captured_at,
        fields=(
            ContextField("application", application),
            ContextField("workspace", "dev"),
        ),
    )
    pixels = bytes((value, value, value) * 81)
    frame = RedactedFrame(
        frame_id=UUID(int=100 + value),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=9,
        height=9,
        stride=27,
        pixel_format=PixelFormat.RGB8,
        pixels=pixels,
        metadata=metadata,
        ocr_text=(text,),
        findings=(),
        policy_revision="policy-v1",
    )
    return RedactedRecord(record_id=UUID(int=value), frame=frame, created_at=captured_at)


def test_extracts_features_only_from_redacted_records_with_one_local_embedding_batch() -> None:
    provider = Embeddings()
    records = (_record(1, "fix parser"), _record(2, "review parser", application="firefox"))

    features = asyncio.run(ActivityFeatureExtractor(provider).extract(records))

    assert tuple(item.record_id for item in features) == (UUID(int=1), UUID(int=2))
    assert tuple(item.application for item in features) == ("emacs", "firefox")
    assert tuple(item.workspace for item in features) == ("dev", "dev")
    assert all(item.perceptual_hash is not None for item in features)
    assert tuple(item.semantic_vector for item in features) == ((1.0, 0.0), (1.0, 1.0))
    assert len(provider.requests) == 1
    assert provider.requests[0].privacy_class is PrivacyClass.REDACTED_CONTENT
    assert provider.requests[0].inputs == (
        "fix parser\napplication:emacs\nworkspace:dev",
        "review parser\napplication:firefox\nworkspace:dev",
    )


def test_remote_embedding_provider_is_rejected_before_content_egress() -> None:
    provider = Embeddings(location=ProviderLocation.REMOTE)

    with pytest.raises(ActivityFeatureFailure, match="local embedding provider required"):
        asyncio.run(ActivityFeatureExtractor(provider).extract((_record(1, "private text"),)))

    assert provider.requests == []


def test_feature_extractor_repr_does_not_contain_record_content() -> None:
    provider = Embeddings()
    extractor = ActivityFeatureExtractor(provider)

    rendered = repr(extractor)

    assert "private text" not in rendered
    assert "synthetic-embedding" not in rendered
