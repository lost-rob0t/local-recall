"""Evidence-bounded cited question answering service."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from local_recall.domain import (
    GenerationRequest,
    GenerationRole,
    ModelCapability,
    PrivacyClass,
    ProviderLocation,
    RoutingRequest,
)
from local_recall.ports.providers import GenerationProvider
from local_recall.retrieval.service import RetrievalBatch, RetrievalQuery
from local_recall.routing import RoutingPolicy

from .evidence import EvidenceTable, build_evidence_table, parse_generated_claims
from .models import AnswerMode, CitedAnswer
from .planner import plan_answer_query

_MAX_OUTPUT_TOKENS = 1024


class RetrievalPort(Protocol):
    """Narrow retrieval dependency used by answering."""

    async def retrieve(self, query: RetrievalQuery) -> RetrievalBatch: ...


class AnsweringFailure(RuntimeError):
    """Sanitized failure while producing a cited answer."""


class AnsweringService:
    """Plan, retrieve, route, generate, and validate one cited answer."""

    __slots__ = ("_local_providers", "_minimum_score", "_retrieval", "_routing")

    def __init__(
        self,
        *,
        retrieval: RetrievalPort,
        routing: RoutingPolicy,
        local_providers: Sequence[GenerationProvider],
        minimum_score: float = 0.20,
    ) -> None:
        if not -1.0 <= minimum_score <= 1.0:
            raise ValueError("minimum evidence score is invalid")
        if not local_providers:
            raise ValueError("answering requires at least one local provider")
        self._retrieval = retrieval
        self._routing = routing
        self._local_providers = tuple(local_providers)
        self._minimum_score = minimum_score

    def __repr__(self) -> str:
        return (
            "AnsweringService("
            f"local_provider_count={len(self._local_providers)}, "
            f"minimum_score={self._minimum_score!r})"
        )

    async def answer(
        self,
        question: str,
        *,
        now: datetime,
        timezone: str,
        mode: AnswerMode,
    ) -> CitedAnswer:
        planned = plan_answer_query(question, now=now, timezone=timezone)
        batch = await self._retrieval.retrieve(planned.retrieval_query)
        table = build_evidence_table(batch, minimum_score=self._minimum_score)
        if not table.items:
            return CitedAnswer(
                mode=mode,
                claims=(),
                insufficient_evidence=True,
                policy_revision=batch.policy_revision,
            )

        capabilities = tuple(await provider.capabilities() for provider in self._local_providers)
        decision = await self._routing.route(
            RoutingRequest(
                capability=ModelCapability.GENERATION,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
            ),
            capabilities,
        )
        if decision.location is not ProviderLocation.LOCAL:
            raise AnsweringFailure("local answering route required")

        provider, provider_capabilities = _select_provider(
            decision.provider_id,
            providers=self._local_providers,
            capabilities=capabilities,
        )
        if not provider_capabilities.supports_structured_output:
            raise AnsweringFailure("structured generation output required")

        context = _generation_context(table)
        total_input_bytes = sum(len(item.encode("utf-8")) for item in context)
        if total_input_bytes > provider_capabilities.max_input_bytes:
            raise AnsweringFailure("answering input exceeds provider limit")

        response = await provider.generate(
            GenerationRequest(
                prompt=_generation_prompt(mode),
                context=context,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                max_output_tokens=_MAX_OUTPUT_TOKENS,
                role=GenerationRole.ANSWERING,
            )
        )
        if response.provider_id != decision.provider_id:
            raise AnsweringFailure("generation provider identity mismatch")

        return parse_generated_claims(
            response.text,
            table=table,
            mode=mode,
            policy_revision=batch.policy_revision,
        )


def _select_provider(
    provider_id: str,
    *,
    providers: tuple[GenerationProvider, ...],
    capabilities: tuple[object, ...],
) -> tuple[GenerationProvider, object]:
    for provider, raw_capabilities in zip(providers, capabilities, strict=True):
        candidate = raw_capabilities
        if getattr(candidate, "provider_id", None) == provider_id:
            return provider, candidate
    raise AnsweringFailure("routed generation provider unavailable")


def _generation_context(table: EvidenceTable) -> tuple[str, ...]:
    return tuple(f"{item.label}: {item.passage.excerpt}" for item in table.items)


def _generation_prompt(mode: AnswerMode) -> str:
    return (
        "Use only the supplied redacted evidence. Return JSON with exactly one top-level key "
        "named claims. claims must be a non-empty array of objects with exactly kind, text, and "
        "evidence_ids. kind is observed or inference. evidence_ids must contain only supplied "
        "opaque evidence labels. Observed text must be copied exactly from cited evidence; "
        "inference may synthesize but must remain explicitly typed as inference. Do not emit "
        f"record IDs, timestamps, citation syntax, or unavailable facts. Answer mode: {mode.value}."
    )
