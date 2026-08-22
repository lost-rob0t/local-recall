from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from local_recall.activity import summaries as activity_summaries
from local_recall.activity.clustering import ActivityCluster
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    ProviderCapabilities,
)


class Generator:
    def __init__(
        self,
        response_text: str,
        *,
        location: ProviderLocation = ProviderLocation.LOCAL,
    ) -> None:
        self.response_text = response_text
        self.location = location
        self.requests: list[GenerationRequest] = []

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="synthetic-generation",
            location=self.location,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=65_536,
            supports_vision=False,
            supports_structured_output=True,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        self.requests.append(request)
        return GenerationResponse(
            text=self.response_text,
            provider_id="synthetic-generation",
            model_id="summary-v1",
        )


def _record(value: int, text: str) -> RedactedRecord:
    captured_at = datetime(2026, 8, 22, 12, value, tzinfo=UTC)
    frame = RedactedFrame(
        frame_id=UUID(int=100 + value),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"\x00\x00\x00",
        metadata=ContextMetadata(observed_at=captured_at, fields=()),
        ocr_text=(text,),
        findings=(),
        policy_revision="policy-v1",
    )
    return RedactedRecord(record_id=UUID(int=value), frame=frame, created_at=captured_at)


def _cluster() -> ActivityCluster:
    return ActivityCluster(
        source_record_ids=(UUID(int=1), UUID(int=2)),
        started_at=datetime(2026, 8, 22, 12, 1, tzinfo=UTC),
        ended_at=datetime(2026, 8, 22, 12, 2, tzinfo=UTC),
    )


def _response(*claims: tuple[UUID, str]) -> str:
    return json.dumps(
        {
            "evidence": [
                {"source_id": str(source_id), "excerpt": excerpt} for source_id, excerpt in claims
            ]
        }
    )


def test_local_model_selects_exact_redacted_evidence_for_summary() -> None:
    provider = Generator(
        _response(
            (UUID(int=1), "implemented parser tests"),
            (UUID(int=2), "fixed parser regression"),
        )
    )
    records = (
        _record(1, "implemented parser tests and reviewed failures"),
        _record(2, "fixed parser regression after review"),
    )

    summary = asyncio.run(
        activity_summaries.ActivitySummarizer(provider).summarize(_cluster(), records)
    )

    assert summary.text == "implemented parser tests\nfixed parser regression"
    assert summary.source_record_ids == (UUID(int=1), UUID(int=2))
    assert summary.provider_id == "synthetic-generation"
    assert summary.model_id == "summary-v1"
    assert len(provider.requests) == 1
    assert provider.requests[0].privacy_class is PrivacyClass.REDACTED_CONTENT
    assert provider.requests[0].role.value == "summarization"
    assert "implemented parser tests and reviewed failures" in provider.requests[0].context


def test_remote_summary_provider_is_rejected_before_content_egress() -> None:
    provider = Generator(_response((UUID(int=1), "private work")), location=ProviderLocation.REMOTE)

    with pytest.raises(
        activity_summaries.ActivitySummaryFailure, match="local generation provider required"
    ):
        asyncio.run(
            activity_summaries.ActivitySummarizer(provider).summarize(
                ActivityCluster(
                    source_record_ids=(UUID(int=1),),
                    started_at=datetime(2026, 8, 22, 12, 1, tzinfo=UTC),
                    ended_at=datetime(2026, 8, 22, 12, 1, tzinfo=UTC),
                ),
                (_record(1, "private work"),),
            )
        )

    assert provider.requests == []


@pytest.mark.parametrize(
    "response_text",
    [
        "not-json",
        "{}",
        json.dumps({"evidence": []}),
        json.dumps({"evidence": [{"source_id": str(UUID(int=9)), "excerpt": "foreign"}]}),
        json.dumps(
            {
                "evidence": [
                    {
                        "source_id": str(UUID(int=1)),
                        "excerpt": "deployed parser to production",
                    }
                ]
            }
        ),
    ],
)
def test_malformed_foreign_or_fabricated_evidence_is_rejected(response_text: str) -> None:
    provider = Generator(response_text)

    with pytest.raises(activity_summaries.ActivitySummaryFailure):
        asyncio.run(
            activity_summaries.ActivitySummarizer(provider).summarize(
                _cluster(),
                (
                    _record(1, "implemented parser tests"),
                    _record(2, "fixed parser regression"),
                ),
            )
        )


def test_summary_repr_hides_generated_text_and_provider_identity() -> None:
    provider = Generator(_response((UUID(int=1), "private work")))
    summary = asyncio.run(
        activity_summaries.ActivitySummarizer(provider).summarize(
            ActivityCluster(
                source_record_ids=(UUID(int=1),),
                started_at=datetime(2026, 8, 22, 12, 1, tzinfo=UTC),
                ended_at=datetime(2026, 8, 22, 12, 1, tzinfo=UTC),
            ),
            (_record(1, "private work"),),
        )
    )

    rendered = repr(summary)
    assert "private work" not in rendered
    assert "synthetic-generation" not in rendered
    assert "summary-v1" not in rendered
