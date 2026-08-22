"""Typed cited-answer domain models."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


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


@dataclass(frozen=True, slots=True)
class AnswerClaim:
    """One answer claim with canonical citations."""

    kind: AnswerClaimKind
    text: str
    citations: tuple[AnswerCitation, ...]


@dataclass(frozen=True, slots=True)
class CitedAnswer:
    """Validated cited answer result."""

    mode: AnswerMode
    claims: tuple[AnswerClaim, ...]
    insufficient_evidence: bool
    policy_revision: str
