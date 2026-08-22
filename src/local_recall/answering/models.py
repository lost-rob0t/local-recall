"""Typed cited-answer domain models."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from local_recall.domain._validation import require_aware, require_nonempty


class AnswerMode(StrEnum):
    """Supported deterministic answer renderings."""

    CONCISE = "concise"
    TIMELINE = "timeline"


class AnswerClaimKind(StrEnum):
    """Evidence status for one generated claim."""

    OBSERVED = "observed"
    INFERENCE = "inference"


@dataclass(frozen=True, slots=True)
class AnswerCitation:
    """Canonical record citation."""

    record_id: UUID
    captured_at: datetime

    def __post_init__(self) -> None:
        require_aware(self.captured_at, "captured_at")


@dataclass(frozen=True, slots=True)
class AnswerClaim:
    """One answer claim with canonical citations."""

    kind: AnswerClaimKind
    text: str
    citations: tuple[AnswerCitation, ...]

    def __post_init__(self) -> None:
        require_nonempty(self.text, "text")
        if not self.citations:
            raise ValueError("citations must not be empty")
        record_ids = tuple(citation.record_id for citation in self.citations)
        if len(set(record_ids)) != len(record_ids):
            raise ValueError("citations must be unique")

    def __repr__(self) -> str:
        return f"AnswerClaim(kind={self.kind!r}, citation_count={len(self.citations)})"


@dataclass(frozen=True, slots=True)
class CitedAnswer:
    """Validated cited answer result."""

    mode: AnswerMode
    claims: tuple[AnswerClaim, ...]
    insufficient_evidence: bool
    policy_revision: str

    def __post_init__(self) -> None:
        require_nonempty(self.policy_revision, "policy_revision")
        if self.insufficient_evidence and self.claims:
            raise ValueError("insufficient answer cannot contain claims")
        if not self.insufficient_evidence and not self.claims:
            raise ValueError("supported answer must contain claims")

    def __repr__(self) -> str:
        return (
            "CitedAnswer("
            f"mode={self.mode!r}, "
            f"claim_count={len(self.claims)}, "
            f"insufficient_evidence={self.insufficient_evidence!r}, "
            f"policy_revision={self.policy_revision!r})"
        )
