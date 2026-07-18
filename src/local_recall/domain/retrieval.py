from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from ._validation import require_aware, require_nonempty


@dataclass(frozen=True, slots=True, repr=False)
class RetrievalHit:
    record_id: UUID
    score: float
    captured_at: datetime
    excerpt: str = field(repr=False)

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("retrieval score must be between 0 and 1")
        require_aware(self.captured_at, "captured_at")


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    query_id: UUID
    started_at: datetime
    completed_at: datetime
    hits: tuple[RetrievalHit, ...]

    def __post_init__(self) -> None:
        require_aware(self.started_at, "started_at")
        require_aware(self.completed_at, "completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("retrieval completion cannot precede start")
        record_ids: set[UUID] = set()
        for hit in self.hits:
            if hit.record_id in record_ids:
                raise ValueError(f"duplicate retrieval hit: {hit.record_id}")
            record_ids.add(hit.record_id)


@dataclass(frozen=True, slots=True)
class Citation:
    citation_id: UUID
    source_record_ids: tuple[UUID, ...]
    answer_start: int
    answer_end: int

    def __post_init__(self) -> None:
        if not self.source_record_ids:
            raise ValueError("citation requires at least one source record")
        if self.answer_start < 0 or self.answer_end <= self.answer_start:
            raise ValueError("citation answer span must be non-empty and non-negative")


@dataclass(frozen=True, slots=True, repr=False)
class CitedAnswer:
    answer: str = field(repr=False)
    citations: tuple[Citation, ...]
    provider_id: str
    model_id: str
    generated_at: datetime
    insufficient_evidence: bool

    def __post_init__(self) -> None:
        require_nonempty(self.provider_id, "provider_id")
        require_nonempty(self.model_id, "model_id")
        require_aware(self.generated_at, "generated_at")
        citation_ids: set[UUID] = set()
        for citation in self.citations:
            if citation.citation_id in citation_ids:
                raise ValueError(f"duplicate citation: {citation.citation_id}")
            citation_ids.add(citation.citation_id)
            if citation.answer_end > len(self.answer):
                raise ValueError("citation span is outside answer")
