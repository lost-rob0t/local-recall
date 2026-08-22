"""Evidence-bounded cited question answering service."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from local_recall.domain import (
    EgressAuthorization,
    EgressDataClass,
    GenerationRequest,
    GenerationResponse,
    GenerationRole,
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
    RoutingRequest,
)
from local_recall.ports.providers import GenerationProvider
from local_recall.retrieval.service import RetrievalBatch, RetrievalQuery
from local_recall.routing import (
    ApprovedEgressPayload,
    EgressGate,
    EgressPayload,
    RoutingPolicy,
)

from .evidence import EvidenceTable, build_evidence_table, parse_generated_claims
from .models import AnswerMode, CitedAnswer
from .planner import plan_answer_query

_MAX_OUTPUT_TOKENS = 1024
_REMOTE_DATA_CLASSES = frozenset({EgressDataClass.REDACTED_TEXT})


class RetrievalPort(Protocol):
    """Narrow retrieval dependency used by answering."""

    async def retrieve(self, query: RetrievalQuery) -> RetrievalBatch: ...


class RemoteGenerationProvider(Protocol):
    """Remote generation boundary that accepts only gate-approved payloads."""

    async def capabilities(self) -> ProviderCapabilities: ...

    async def generate(self, approved: ApprovedEgressPayload) -> GenerationResponse: ...


class AnsweringFailure(RuntimeError):
    """Sanitized failure while producing a cited answer."""


class AnsweringService:
    """Plan, retrieve, route, generate, and validate one cited answer."""

    __slots__ = (
        "_egress_gate",
        "_local_providers",
        "_minimum_score",
        "_remote_providers",
        "_retrieval",
        "_routing",
    )

    def __init__(
        self,
        *,
        retrieval: RetrievalPort,
        routing: RoutingPolicy,
        local_providers: Sequence[GenerationProvider] = (),
        remote_providers: Sequence[RemoteGenerationProvider] = (),
        egress_gate: EgressGate | None = None,
        minimum_score: float = 0.20,
    ) -> None:
        if not -1.0 <= minimum_score <= 1.0:
            raise ValueError("minimum evidence score is invalid")
        if not local_providers and not remote_providers:
            raise ValueError("answering requires at least one provider")
        self._retrieval = retrieval
        self._routing = routing
        self._local_providers = tuple(local_providers)
        self._remote_providers = tuple(remote_providers)
        self._egress_gate = egress_gate
        self._minimum_score = minimum_score

    def __repr__(self) -> str:
        return (
            "AnsweringService("
            f"local_provider_count={len(self._local_providers)}, "
            f"remote_provider_count={len(self._remote_providers)}, "
            f"minimum_score={self._minimum_score!r})"
        )

    async def answer(
        self,
        question: str,
        *,
        now: datetime,
        timezone: str,
        mode: AnswerMode,
        egress_authorization: EgressAuthorization | None = None,
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

        local_capabilities = await _provider_capabilities(self._local_providers)
        remote_capabilities = await _provider_capabilities(self._remote_providers)
        capabilities = local_capabilities + remote_capabilities
        allow_remote = egress_authorization is not None
        decision = await self._routing.route(
            RoutingRequest(
                capability=ModelCapability.GENERATION,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                allow_remote=allow_remote,
                egress_authorization_id=(
                    egress_authorization.authorization_id if egress_authorization is not None else None
                ),
                data_classes=_REMOTE_DATA_CLASSES if allow_remote else frozenset(),
                authorization=egress_authorization,
            ),
            capabilities,
        )

        prompt = _generation_prompt(mode)
        context = _generation_context(table)
        if decision.location is ProviderLocation.LOCAL:
            response = await self._generate_local(
                decision.provider_id,
                prompt=prompt,
                context=context,
                capabilities=local_capabilities,
            )
        else:
            response = await self._generate_remote(
                decision.provider_id,
                prompt=prompt,
                context=context,
                capabilities=remote_capabilities,
                batch=batch,
                authorization=egress_authorization,
            )

        if response.provider_id != decision.provider_id:
            raise AnsweringFailure("generation provider identity mismatch")

        return parse_generated_claims(
            response.text,
            table=table,
            mode=mode,
            policy_revision=batch.policy_revision,
        )

    async def _generate_local(
        self,
        provider_id: str,
        *,
        prompt: str,
        context: tuple[str, ...],
        capabilities: tuple[ProviderCapabilities, ...],
    ) -> GenerationResponse:
        provider, provider_capabilities = _select_provider(
            provider_id,
            providers=self._local_providers,
            capabilities=capabilities,
        )
        _validate_generation_capabilities(provider_capabilities, prompt=prompt, context=context)
        return await provider.generate(
            GenerationRequest(
                prompt=prompt,
                context=context,
                privacy_class=PrivacyClass.REDACTED_CONTENT,
                max_output_tokens=_MAX_OUTPUT_TOKENS,
                role=GenerationRole.ANSWERING,
            )
        )

    async def _generate_remote(
        self,
        provider_id: str,
        *,
        prompt: str,
        context: tuple[str, ...],
        capabilities: tuple[ProviderCapabilities, ...],
        batch: RetrievalBatch,
        authorization: EgressAuthorization | None,
    ) -> GenerationResponse:
        if not batch.remote_provider_eligible:
            raise AnsweringFailure("remote retrieval not eligible")
        if authorization is None or authorization.provider_id != provider_id:
            raise AnsweringFailure("remote egress authorization required")
        if self._egress_gate is None:
            raise AnsweringFailure("remote egress gate unavailable")

        provider, provider_capabilities = _select_provider(
            provider_id,
            providers=self._remote_providers,
            capabilities=capabilities,
        )
        _validate_generation_capabilities(provider_capabilities, prompt=prompt, context=context)
        payload = EgressPayload(text=_remote_prompt(prompt, context))
        approved = self._egress_gate.approve(payload, authorization)
        return await provider.generate(approved)


def _select_provider[ProviderT](
    provider_id: str,
    *,
    providers: tuple[ProviderT, ...],
    capabilities: tuple[ProviderCapabilities, ...],
) -> tuple[ProviderT, ProviderCapabilities]:
    for provider, candidate in zip(providers, capabilities, strict=True):
        if candidate.provider_id == provider_id:
            return provider, candidate
    raise AnsweringFailure("routed generation provider unavailable")


async def _provider_capabilities(
    providers: Sequence[GenerationProvider | RemoteGenerationProvider],
) -> tuple[ProviderCapabilities, ...]:
    capabilities: list[ProviderCapabilities] = []
    for provider in providers:
        capabilities.append(await provider.capabilities())
    return tuple(capabilities)


def _validate_generation_capabilities(
    capabilities: ProviderCapabilities,
    *,
    prompt: str,
    context: tuple[str, ...],
) -> None:
    if not capabilities.supports_structured_output:
        raise AnsweringFailure("structured generation output required")
    total_input_bytes = len(prompt.encode("utf-8")) + sum(
        len(item.encode("utf-8")) for item in context
    )
    if total_input_bytes > capabilities.max_input_bytes:
        raise AnsweringFailure("answering input exceeds provider limit")


def _generation_context(table: EvidenceTable) -> tuple[str, ...]:
    return tuple(f"{item.label}: {item.passage.excerpt}" for item in table.items)


def _remote_prompt(prompt: str, context: tuple[str, ...]) -> str:
    evidence = "\n".join(context)
    return f"{prompt}\n\nEvidence:\n{evidence}"


def _generation_prompt(mode: AnswerMode) -> str:
    return (
        "Use only the supplied redacted evidence. Return JSON with exactly one top-level key "
        "named claims. claims must be a non-empty array of objects with exactly kind, text, and "
        "evidence_ids. kind is observed or inference. evidence_ids must contain only supplied "
        "opaque evidence labels. Observed text must be copied exactly from cited evidence; "
        "inference may synthesize but must remain explicitly typed as inference. Do not emit "
        f"record IDs, timestamps, citation syntax, or unavailable facts. Answer mode: {mode.value}."
    )
