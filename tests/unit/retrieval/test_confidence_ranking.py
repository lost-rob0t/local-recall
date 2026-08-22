from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.retrieval.service import (
    RetrievalPolicyDecision,
    RetrievalQuery,
    RetrievalService,
)
from local_recall.retrieval.time import ResolvedTimeRange

from .test_service import FakeEncryption, FakePolicy, FakeStorage


def _record(captured_at: datetime, confidence: float) -> RedactedRecord:
    provenance = MetadataProvenance(
        source_id="synthetic-metadata",
        observed_at=captured_at,
        confidence=SourceConfidence(confidence),
        adapter_revision="test-v1",
    )
    metadata = ContextMetadata(
        observed_at=captured_at,
        fields=(
            ContextField("application", "emacs", (provenance,)),
            ContextField("workspace", "dev", (provenance,)),
        ),
    )
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIX",
        metadata=metadata,
        ocr_text=("same relevance",),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=uuid4(), frame=frame, created_at=captured_at)


def test_plain_retrieval_ranks_higher_confidence_before_earlier_low_confidence() -> None:
    earlier_low = _record(datetime(2026, 8, 22, 10, 5, tzinfo=UTC), 0.2)
    later_high = _record(datetime(2026, 8, 22, 10, 10, tzinfo=UTC), 0.95)
    records = (earlier_low, later_high)
    storage = FakeStorage(records)
    encryption = FakeEncryption(records)
    policy = FakePolicy(
        RetrievalPolicyDecision(
            allowed=True,
            remote_provider_eligible=False,
            policy_revision="query-policy-v1",
            reason_code="allowed",
        )
    )
    service = RetrievalService(storage=storage, encryption=encryption, policy=policy)
    query = RetrievalQuery(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 11, 0, tzinfo=UTC),
        ),
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert tuple(item.record_id for item in result.passages) == (
        later_high.record_id,
        earlier_low.record_id,
    )
    assert result.passages[0].score == 0.95
    assert result.passages[1].score == 0.2
