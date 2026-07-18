from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    ModelCapability,
    ProviderCapabilities,
    RoutingDecision,
)
from local_recall.domain.retrieval import Citation, CitedAnswer, RetrievalHit, RetrievalResult


def test_remote_routing_requires_explicit_egress_authorization() -> None:
    with pytest.raises(ValueError, match="egress authorization"):
        RoutingDecision(
            provider_id="remote-provider",
            location=ProviderLocation.REMOTE,
            capability=ModelCapability.GENERATION,
            egress_authorization_id=None,
            reason_code="remote-selected",
        )


def test_provider_capabilities_make_privacy_classes_explicit() -> None:
    capabilities = ProviderCapabilities(
        provider_id="local-model",
        location=ProviderLocation.LOCAL,
        capabilities=frozenset({ModelCapability.GENERATION}),
        accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
        max_input_bytes=1024,
        supports_vision=False,
    )

    assert capabilities.accepts(PrivacyClass.REDACTED_CONTENT)
    assert not capabilities.accepts(PrivacyClass.RAW_CAPTURE)


def test_retrieval_result_rejects_duplicate_records() -> None:
    record_id = uuid4()
    hit = RetrievalHit(
        record_id=record_id,
        score=0.9,
        captured_at=datetime.now(UTC),
        excerpt="synthetic excerpt",
    )

    with pytest.raises(ValueError, match="duplicate retrieval hit"):
        RetrievalResult(
            query_id=uuid4(),
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            hits=(hit, hit),
        )


def test_cited_answer_validates_answer_spans() -> None:
    citation = Citation(
        citation_id=uuid4(),
        source_record_ids=(uuid4(),),
        answer_start=0,
        answer_end=99,
    )

    with pytest.raises(ValueError, match="outside answer"):
        CitedAnswer(
            answer="short",
            citations=(citation,),
            provider_id="local-model",
            model_id="synthetic",
            generated_at=datetime.now(UTC),
            insufficient_evidence=False,
        )
