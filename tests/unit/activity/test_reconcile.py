from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from local_recall.activity import reconcile as activity_reconcile
from local_recall.activity.clustering import ActivityClusteringPolicy, ActivitySegmenter
from local_recall.activity.features import ActivityFeatureExtractor
from local_recall.activity.store import EncryptedActivityStore
from local_recall.activity.summaries import ActivitySummarizer
from local_recall.crypto import OSKeyringProvider
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    ProviderCapabilities,
)


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


class Embeddings:
    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="local-embedding",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.EMBEDDING}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=65_536,
            supports_vision=False,
        )

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        return EmbeddingResponse(
            provider_id="local-embedding",
            model_id="embed-v1",
            vectors=tuple((1.0, 0.0) for _ in request.inputs),
        )


class Generator:
    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.malformed = False
        self.requests: list[GenerationRequest] = []

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="local-generation",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=65_536,
            supports_vision=False,
            supports_structured_output=True,
            available=self.available,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        self.requests.append(request)
        if self.malformed:
            return GenerationResponse(
                provider_id="local-generation",
                model_id="summary-v1",
                text='{"evidence":[{"source_id":"00000000-0000-4000-8000-ffffffffffff","excerpt":"invented"}]}',
            )
        source_id = re.findall(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            request.prompt,
        )[0]
        return GenerationResponse(
            provider_id="local-generation",
            model_id="summary-v1",
            text=json.dumps(
                {
                    "evidence": [
                        {
                            "source_id": source_id,
                            "excerpt": request.context[0],
                        }
                    ]
                }
            ),
        )


def _record(
    value: int,
    text: str,
    *,
    policy_revision: str = "policy-v1",
) -> RedactedRecord:
    captured_at = datetime(2026, 8, 22, 12, value, tzinfo=UTC)
    provenance = (
        MetadataProvenance(
            source_id="synthetic",
            observed_at=captured_at,
            confidence=SourceConfidence(1.0),
            adapter_revision="test-v1",
        ),
    )
    metadata = ContextMetadata(
        observed_at=captured_at,
        fields=(
            ContextField("application", "emacs", provenance),
            ContextField("workspace", "dev", provenance),
        ),
    )
    frame = RedactedFrame(
        frame_id=UUID(int=100 + value),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=9,
        height=9,
        stride=27,
        pixel_format=PixelFormat.RGB8,
        pixels=bytes((value, value, value) * 81),
        metadata=metadata,
        ocr_text=(text,),
        findings=(),
        policy_revision=policy_revision,
    )
    return RedactedRecord(record_id=UUID(int=value), frame=frame, created_at=captured_at)


def _reconciler(
    root: Path,
    generator: Generator,
) -> tuple[activity_reconcile.ActivityReconciler, EncryptedActivityStore]:
    store = EncryptedActivityStore(
        root,
        OSKeyringProvider(MemoryKeyringBackend()),
    )
    policy = ActivityClusteringPolicy(
        max_gap_seconds=600.0,
        strong_gap_seconds=120.0,
        minimum_continuity_score=0.5,
        minimum_semantic_similarity=0.5,
    )
    reconciler = activity_reconcile.ActivityReconciler(
        feature_extractor=ActivityFeatureExtractor(Embeddings()),
        segmenter=ActivitySegmenter(policy),
        summarizer=ActivitySummarizer(generator),
        store=store,
    )
    return reconciler, store


def test_reconcile_reuses_unchanged_summary_and_regenerates_after_deletion(tmp_path: Path) -> None:
    generator = Generator()
    reconciler, store = _reconciler(tmp_path / "activity", generator)
    first = _record(1, "fix parser")
    second = _record(2, "review parser")

    initial = asyncio.run(reconciler.reconcile((first, second)))
    repeated = asyncio.run(reconciler.reconcile((first, second)))
    after_delete = asyncio.run(reconciler.reconcile((second,)))

    assert initial == repeated
    assert len(generator.requests) == 2
    assert initial.entries[0].summary is not None
    assert after_delete.entries[0].cluster.source_record_ids == (second.record_id,)
    assert after_delete.entries[0].summary is not None
    assert asyncio.run(store.load()) == after_delete


def test_policy_or_redacted_content_change_forces_summary_regeneration(tmp_path: Path) -> None:
    generator = Generator()
    reconciler, _ = _reconciler(tmp_path / "activity", generator)
    original = _record(1, "fix parser")
    changed = _record(1, "fix parser safely", policy_revision="policy-v2")

    first = asyncio.run(reconciler.reconcile((original,)))
    second = asyncio.run(reconciler.reconcile((changed,)))

    assert len(generator.requests) == 2
    assert first.entries[0].source_fingerprint != second.entries[0].source_fingerprint
    assert second.entries[0].policy_revisions == ("policy-v2",)


def test_unavailable_generation_keeps_deterministic_clusters_without_summary(tmp_path: Path) -> None:
    generator = Generator(available=False)
    reconciler, store = _reconciler(tmp_path / "activity", generator)

    snapshot = asyncio.run(reconciler.reconcile((_record(1, "fix parser"),)))

    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].summary is None
    assert generator.requests == []
    assert asyncio.run(store.load()) == snapshot


def test_invalid_generated_evidence_preserves_previous_authoritative_snapshot(tmp_path: Path) -> None:
    generator = Generator()
    reconciler, store = _reconciler(tmp_path / "activity", generator)
    original = _record(1, "fix parser")
    changed = _record(1, "review parser")
    previous = asyncio.run(reconciler.reconcile((original,)))
    generator.malformed = True

    with pytest.raises(Exception, match="activity summary"):
        asyncio.run(reconciler.reconcile((changed,)))

    assert asyncio.run(store.load()) == previous
