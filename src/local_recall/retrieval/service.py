from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from local_recall.domain._validation import require_aware, require_nonempty
from local_recall.domain.frames import RedactedRecord
from local_recall.domain.metadata import MetadataScalar
from local_recall.ports.encryption import DecryptionRequest, EncryptionProvider
from local_recall.ports.storage import CatalogRecord, DayRangeQuery, QueryableStorageBackend

from .time import ResolvedTimeRange

_MAX_RESULT_LIMIT = 1000
_MAX_CANDIDATE_LIMIT = 10_000
_MAX_EXCERPT_CHARS = 4096
_METADATA_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


@dataclass(frozen=True, slots=True, repr=False)
class MetadataFilter:
    field_name: str
    value: MetadataScalar = field(repr=False)

    def __post_init__(self) -> None:
        if not _METADATA_FIELD_NAME.fullmatch(self.field_name):
            raise ValueError("metadata filter field name is invalid")

    def __repr__(self) -> str:
        return f"MetadataFilter(field_name={self.field_name!r}, value=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RetrievalQuery:
    time_range: ResolvedTimeRange
    application: str | None = field(default=None, repr=False)
    workspace: str | None = field(default=None, repr=False)
    keywords: tuple[str, ...] = field(default=(), repr=False)
    semantic_text: str | None = field(default=None, repr=False)
    metadata_filters: tuple[MetadataFilter, ...] = field(default=(), repr=False)
    limit: int = 100
    candidate_limit: int = 1024
    query_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if self.application is not None:
            require_nonempty(self.application, "application")
        if self.workspace is not None:
            require_nonempty(self.workspace, "workspace")
        if self.semantic_text is not None:
            require_nonempty(self.semantic_text, "semantic_text")
        normalized_keywords = tuple(keyword.strip().casefold() for keyword in self.keywords)
        if any(not keyword for keyword in normalized_keywords):
            raise ValueError("retrieval keywords must not be empty")
        if len(set(normalized_keywords)) != len(normalized_keywords):
            raise ValueError("retrieval keywords must be unique")
        filter_names = tuple(item.field_name for item in self.metadata_filters)
        if len(filter_names) != len(set(filter_names)):
            raise ValueError("retrieval metadata filter fields must be unique")
        if not 1 <= self.limit <= _MAX_RESULT_LIMIT:
            raise ValueError("retrieval limit is invalid")
        if not 1 <= self.candidate_limit <= _MAX_CANDIDATE_LIMIT:
            raise ValueError("retrieval candidate limit is invalid")
        if self.limit > self.candidate_limit:
            raise ValueError("retrieval limit exceeds candidate limit")
        object.__setattr__(self, "keywords", normalized_keywords)

    def __repr__(self) -> str:
        return (
            f"RetrievalQuery(query_id={self.query_id!r}, time_range={self.time_range!r}, "
            f"application_filter={self.application is not None}, "
            f"workspace_filter={self.workspace is not None}, "
            f"keyword_count={len(self.keywords)}, "
            f"semantic_filter={self.semantic_text is not None}, "
            f"metadata_filter_count={len(self.metadata_filters)}, "
            f"limit={self.limit}, candidate_limit={self.candidate_limit})"
        )


@dataclass(frozen=True, slots=True)
class RetrievalPolicyDecision:
    allowed: bool
    remote_provider_eligible: bool
    policy_revision: str
    reason_code: str

    def __post_init__(self) -> None:
        require_nonempty(self.policy_revision, "policy_revision")
        require_nonempty(self.reason_code, "reason_code")
        if not self.allowed and self.remote_provider_eligible:
            raise ValueError("denied retrieval cannot allow remote provider")


@dataclass(frozen=True, slots=True)
class SemanticCandidate:
    record_id: UUID
    captured_at: datetime
    score: float

    def __post_init__(self) -> None:
        require_aware(self.captured_at, "captured_at")
        if not -1.0 <= self.score <= 1.0:
            raise ValueError("semantic score is invalid")


@runtime_checkable
class SemanticSearch(Protocol):
    async def search(
        self,
        text: str,
        *,
        start_at: datetime,
        end_at: datetime,
        limit: int,
    ) -> tuple[SemanticCandidate, ...]: ...


@dataclass(frozen=True, slots=True)
class RetrievedMetadataProvenance:
    field_name: str
    source_id: str
    observed_at: datetime
    confidence: float
    adapter_revision: str | None

    def __post_init__(self) -> None:
        require_nonempty(self.field_name, "field_name")
        require_nonempty(self.source_id, "source_id")
        require_aware(self.observed_at, "observed_at")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("retrieval provenance confidence is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class RetrievedPassage:
    record_id: UUID
    captured_at: datetime
    excerpt: str = field(repr=False)
    score: float
    metadata_provenance: tuple[RetrievedMetadataProvenance, ...]
    redaction_policy_revision: str
    redaction_finding_count: int

    def __post_init__(self) -> None:
        require_aware(self.captured_at, "captured_at")
        if not -1.0 <= self.score <= 1.0:
            raise ValueError("retrieval score is invalid")
        require_nonempty(self.redaction_policy_revision, "redaction_policy_revision")
        if self.redaction_finding_count < 0:
            raise ValueError("redaction finding count is invalid")

    def __repr__(self) -> str:
        return (
            f"RetrievedPassage(record_id={self.record_id!r}, "
            f"captured_at={self.captured_at!r}, score={self.score!r}, "
            f"excerpt_length={len(self.excerpt)}, "
            f"metadata_provenance_count={len(self.metadata_provenance)}, "
            f"redaction_policy_revision={self.redaction_policy_revision!r}, "
            f"redaction_finding_count={self.redaction_finding_count})"
        )


@dataclass(frozen=True, slots=True)
class RetrievalBatch:
    query_id: UUID
    passages: tuple[RetrievedPassage, ...]
    remote_provider_eligible: bool
    policy_revision: str

    def __post_init__(self) -> None:
        require_nonempty(self.policy_revision, "policy_revision")
        ids = tuple(passage.record_id for passage in self.passages)
        if len(ids) != len(set(ids)):
            raise ValueError("retrieval batch contains duplicate records")


@runtime_checkable
class RetrievalPolicy(Protocol):
    async def authorize_query(self, query: RetrievalQuery) -> RetrievalPolicyDecision: ...

    async def authorize_record(
        self, query: RetrievalQuery, record: RedactedRecord
    ) -> RetrievalPolicyDecision: ...


class RetrievalService:
    def __init__(
        self,
        *,
        storage: QueryableStorageBackend,
        encryption: EncryptionProvider,
        policy: RetrievalPolicy,
        semantic_search: SemanticSearch | None = None,
    ) -> None:
        self._storage = storage
        self._encryption = encryption
        self._policy = policy
        self._semantic_search = semantic_search

    async def retrieve(self, query: RetrievalQuery) -> RetrievalBatch:
        query_decision = await self._policy.authorize_query(query)
        if not query_decision.allowed:
            return _empty_batch(query, query_decision)

        start_utc = query.time_range.start_at.astimezone(UTC)
        last_included_utc = query.time_range.end_at.astimezone(UTC) - timedelta(microseconds=1)
        candidates = await self._storage.list_candidates(
            DayRangeQuery(
                start_day=start_utc.date(),
                end_day=last_included_utc.date(),
                limit=query.candidate_limit,
            )
        )
        semantic_scores = await self._semantic_scores(query, candidates)
        if query.semantic_text is not None and not semantic_scores:
            return RetrievalBatch(
                query_id=query.query_id,
                passages=(),
                remote_provider_eligible=False,
                policy_revision=query_decision.policy_revision,
            )

        passages: list[RetrievedPassage] = []
        remote_provider_eligible = query_decision.remote_provider_eligible
        for candidate in candidates:
            record_id = candidate.record.record_id
            if query.semantic_text is not None and record_id not in semantic_scores:
                continue
            envelope = await self._storage.get(record_id)
            if envelope is None:
                continue
            record = await self._encryption.decrypt(DecryptionRequest(envelope, envelope.key))
            if not _matches(query, record):
                continue
            record_decision = await self._policy.authorize_record(query, record)
            if record_decision.policy_revision != query_decision.policy_revision:
                return RetrievalBatch(
                    query_id=query.query_id,
                    passages=(),
                    remote_provider_eligible=False,
                    policy_revision=record_decision.policy_revision,
                )
            if not record_decision.allowed:
                continue
            remote_provider_eligible = (
                remote_provider_eligible and record_decision.remote_provider_eligible
            )
            passages.append(_passage(record, query, semantic_scores.get(record_id)))

        passages.sort(key=lambda item: (-item.score, item.captured_at, str(item.record_id)))
        return RetrievalBatch(
            query_id=query.query_id,
            passages=tuple(passages[: query.limit]),
            remote_provider_eligible=remote_provider_eligible,
            policy_revision=query_decision.policy_revision,
        )

    async def _semantic_scores(
        self,
        query: RetrievalQuery,
        candidates: tuple[CatalogRecord, ...],
    ) -> dict[UUID, float]:
        if query.semantic_text is None:
            return {}
        if self._semantic_search is None:
            raise RuntimeError("semantic retrieval is unavailable")
        hits = await self._semantic_search.search(
            query.semantic_text,
            start_at=query.time_range.start_at,
            end_at=query.time_range.end_at,
            limit=query.candidate_limit,
        )
        canonical_ids = {candidate.record.record_id for candidate in candidates}
        scores: dict[UUID, float] = {}
        for hit in hits:
            if hit.record_id in canonical_ids:
                scores[hit.record_id] = max(scores.get(hit.record_id, -1.0), hit.score)
        return scores


def _empty_batch(query: RetrievalQuery, decision: RetrievalPolicyDecision) -> RetrievalBatch:
    return RetrievalBatch(
        query_id=query.query_id,
        passages=(),
        remote_provider_eligible=False,
        policy_revision=decision.policy_revision,
    )


def _matches(query: RetrievalQuery, record: RedactedRecord) -> bool:
    captured_at = record.frame.captured_at
    if not query.time_range.start_at <= captured_at < query.time_range.end_at:
        return False
    if query.application is not None and not _metadata_matches(
        record, "application", query.application
    ):
        return False
    if query.workspace is not None and not _metadata_matches(record, "workspace", query.workspace):
        return False
    if any(not _metadata_filter_matches(record, item) for item in query.metadata_filters):
        return False
    if query.keywords:
        haystack = "\n".join(record.frame.ocr_text).casefold()
        if any(keyword not in haystack for keyword in query.keywords):
            return False
    return True


def _metadata_matches(record: RedactedRecord, field_name: str, expected: str) -> bool:
    value = record.frame.metadata.get(field_name)
    return isinstance(value, str) and value.casefold() == expected.casefold()


def _metadata_filter_matches(record: RedactedRecord, metadata_filter: MetadataFilter) -> bool:
    for context_field in record.frame.metadata.fields:
        if context_field.name != metadata_filter.field_name:
            continue
        actual = context_field.value
        expected = metadata_filter.value
        return type(actual) is type(expected) and actual == expected
    return False


def _passage(
    record: RedactedRecord,
    query: RetrievalQuery,
    semantic_score: float | None,
) -> RetrievedPassage:
    text = "\n".join(record.frame.ocr_text)
    excerpt = text[:_MAX_EXCERPT_CHARS]
    provenance = tuple(
        RetrievedMetadataProvenance(
            field_name=context_field.name,
            source_id=item.source_id,
            observed_at=item.observed_at,
            confidence=item.confidence.value,
            adapter_revision=item.adapter_revision,
        )
        for context_field in record.frame.metadata.fields
        for item in context_field.provenance
    )
    score = semantic_score if semantic_score is not None else 1.0
    if semantic_score is None and query.keywords:
        haystack = text.casefold()
        score = sum(keyword in haystack for keyword in query.keywords) / len(query.keywords)
    return RetrievedPassage(
        record_id=record.record_id,
        captured_at=record.frame.captured_at,
        excerpt=excerpt,
        score=score,
        metadata_provenance=provenance,
        redaction_policy_revision=record.frame.policy_revision,
        redaction_finding_count=len(record.frame.findings),
    )
