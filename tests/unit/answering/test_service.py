import asyncio
import importlib
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from local_recall.answering.models import AnswerMode, CitedAnswer
from local_recall.domain import (
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
)
from local_recall.retrieval.service import RetrievalBatch, RetrievalQuery, RetrievedPassage
from local_recall.routing import RoutingMode, RoutingPolicy

service_module = importlib.import_module("local_recall.answering.service")

RECORD = UUID("00000000-0000-0000-0000-000000000301")
CAPTURED = datetime(2026, 8, 22, 14, 0, tzinfo=UTC)
NOW = datetime(2026, 8, 24, 15, 30, tzinfo=UTC)


class AnswerService(Protocol):
    def answer(
        self,
        question: str,
        *,
        now: datetime,
        timezone: str,
        mode: AnswerMode,
    ) -> Coroutine[object, object, CitedAnswer]: ...


class FakeRetrieval:
    def __init__(self, score: float = 0.91) -> None:
        self.score = score
        self.queries: list[RetrievalQuery] = []

    async def retrieve(self, query: RetrievalQuery) -> RetrievalBatch:
        self.queries.append(query)
        return RetrievalBatch(
            query_id=query.query_id,
            passages=(
                RetrievedPassage(
                    record_id=RECORD,
                    captured_at=CAPTURED,
                    excerpt="Edited the design document.",
                    score=self.score,
                    metadata_provenance=(),
                    redaction_policy_revision="redaction-v3",
                    redaction_finding_count=1,
                ),
            ),
            remote_provider_eligible=False,
            policy_revision="policy-v8",
        )


class FakeLocalProvider:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.requests: list[GenerationRequest] = []

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="local-answer",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=64 * 1024,
            supports_vision=False,
            supports_structured_output=True,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("synthetic local failure")
        return GenerationResponse(
            text=(
                '{"claims":[{"kind":"observed","text":"Edited the design document.",'
                '"evidence_ids":["E1"]}]}'
            ),
            provider_id="local-answer",
            model_id="fixture-model",
        )


def make_service(retrieval: FakeRetrieval, provider: FakeLocalProvider) -> AnswerService:
    factory = cast(
        Callable[..., AnswerService],
        getattr(service_module, "AnsweringService"),
    )
    return factory(
        retrieval=retrieval,
        routing=RoutingPolicy(RoutingMode.LOCAL_ONLY),
        local_providers=(provider,),
        minimum_score=0.20,
    )


def test_local_only_answers_from_retrieved_evidence_with_canonical_citation() -> None:
    retrieval = FakeRetrieval()
    provider = FakeLocalProvider()
    service = make_service(retrieval, provider)

    answer = asyncio.run(
        service.answer(
            "What was I doing Saturday?",
            now=NOW,
            timezone="America/New_York",
            mode=AnswerMode.CONCISE,
        )
    )

    assert answer.insufficient_evidence is False
    assert answer.claims[0].citations[0].record_id == RECORD
    assert answer.claims[0].citations[0].captured_at == CAPTURED
    assert len(provider.requests) == 1
    assert provider.requests[0].role.value == "answering"
    assert provider.requests[0].privacy_class is PrivacyClass.REDACTED_CONTENT
    assert "E1" in provider.requests[0].context[0]
    assert str(RECORD) not in provider.requests[0].context[0]


def test_weak_retrieval_returns_insufficient_evidence_without_generation() -> None:
    retrieval = FakeRetrieval(score=0.04)
    provider = FakeLocalProvider()
    service = make_service(retrieval, provider)

    answer = asyncio.run(
        service.answer(
            "What was I doing Saturday?",
            now=NOW,
            timezone="America/New_York",
            mode=AnswerMode.CONCISE,
        )
    )

    assert answer.insufficient_evidence is True
    assert answer.claims == ()
    assert provider.requests == []


def test_local_provider_failure_does_not_fallback_to_another_route() -> None:
    retrieval = FakeRetrieval()
    provider = FakeLocalProvider(fail=True)
    service = make_service(retrieval, provider)

    try:
        asyncio.run(
            service.answer(
                "What was I doing Saturday?",
                now=NOW,
                timezone="America/New_York",
                mode=AnswerMode.CONCISE,
            )
        )
    except RuntimeError as exc:
        assert "synthetic local failure" in str(exc)
    else:
        raise AssertionError("expected local provider failure")

    assert len(provider.requests) == 1
