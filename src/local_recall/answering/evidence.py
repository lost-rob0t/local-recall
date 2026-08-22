"""Evidence labeling and strict generated-claim validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from local_recall.domain._validation import require_nonempty
from local_recall.retrieval.service import RetrievalBatch, RetrievedPassage

from .models import AnswerCitation, AnswerClaim, AnswerClaimKind, AnswerMode, CitedAnswer

_MAX_CLAIMS = 32
_MAX_CLAIM_CHARS = 4096


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceItem:
    """One request-local opaque label mapped to canonical retrieval evidence."""

    label: str
    passage: RetrievedPassage

    def __post_init__(self) -> None:
        require_nonempty(self.label, "evidence label")

    def __repr__(self) -> str:
        return (
            "EvidenceItem("
            f"label={self.label!r}, record_id={self.passage.record_id!r}, "
            f"captured_at={self.passage.captured_at!r}, score={self.passage.score!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceTable:
    """Bounded request-local evidence map."""

    items: tuple[EvidenceItem, ...]

    def __post_init__(self) -> None:
        labels = tuple(item.label for item in self.items)
        if len(labels) != len(set(labels)):
            raise ValueError("evidence labels must be unique")
        record_ids = tuple(item.passage.record_id for item in self.items)
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("evidence records must be unique")

    def __repr__(self) -> str:
        return f"EvidenceTable(item_count={len(self.items)})"


def build_evidence_table(
    batch: RetrievalBatch,
    *,
    minimum_score: float,
) -> EvidenceTable:
    """Filter weak passages and assign deterministic request-local labels."""

    if not -1.0 <= minimum_score <= 1.0:
        raise ValueError("minimum evidence score is invalid")
    selected = tuple(passage for passage in batch.passages if passage.score >= minimum_score)
    return EvidenceTable(
        items=tuple(
            EvidenceItem(label=f"E{index}", passage=passage)
            for index, passage in enumerate(selected, start=1)
        )
    )


def parse_generated_claims(
    text: str,
    *,
    table: EvidenceTable,
    mode: AnswerMode,
    policy_revision: str,
) -> CitedAnswer:
    """Validate closed generated claims and reconstruct canonical citations."""

    require_nonempty(text, "generated claims")
    raw = _load_json_object(text)
    if set(raw) != {"claims"} or not isinstance(raw["claims"], list):
        raise ValueError("generated claim schema is invalid")
    raw_claims = raw["claims"]
    if not raw_claims or len(raw_claims) > _MAX_CLAIMS:
        raise ValueError("generated claim schema is invalid")

    by_label = {item.label: item for item in table.items}
    claims = tuple(_parse_claim(item, by_label=by_label) for item in raw_claims)
    if mode is AnswerMode.TIMELINE:
        claims = tuple(sorted(claims, key=_timeline_key))
    return CitedAnswer(
        mode=mode,
        claims=claims,
        insufficient_evidence=False,
        policy_revision=policy_revision,
    )


def _load_json_object(text: str) -> dict[str, Any]:
    try:
        raw = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("generated claim schema is invalid") from exc
    if not isinstance(raw, dict):
        raise ValueError("generated claim schema is invalid")
    return raw


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_claim(raw: object, *, by_label: dict[str, EvidenceItem]) -> AnswerClaim:
    if not isinstance(raw, dict) or set(raw) != {"kind", "text", "evidence_ids"}:
        raise ValueError("generated claim schema is invalid")
    kind_value = raw["kind"]
    text = raw["text"]
    evidence_ids = raw["evidence_ids"]
    if not isinstance(kind_value, str) or not isinstance(text, str):
        raise ValueError("generated claim schema is invalid")
    if not text.strip() or len(text) > _MAX_CLAIM_CHARS:
        raise ValueError("generated claim schema is invalid")
    try:
        kind = AnswerClaimKind(kind_value)
    except ValueError as exc:
        raise ValueError("generated claim schema is invalid") from exc
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or any(not isinstance(label, str) for label in evidence_ids)
        or len(set(evidence_ids)) != len(evidence_ids)
        or any(label not in by_label for label in evidence_ids)
    ):
        raise ValueError("generated claim evidence is invalid")

    selected = tuple(by_label[label] for label in evidence_ids)
    if kind is AnswerClaimKind.OBSERVED and not _observed_supported(text, selected):
        raise ValueError("observed claim is unsupported")
    citations = tuple(
        AnswerCitation(
            record_id=item.passage.record_id,
            captured_at=item.passage.captured_at,
        )
        for item in selected
    )
    return AnswerClaim(kind=kind, text=text.strip(), citations=citations)


def _observed_supported(text: str, items: tuple[EvidenceItem, ...]) -> bool:
    claim = _normalize_support_text(text)
    return any(claim in _normalize_support_text(item.passage.excerpt) for item in items)


def _normalize_support_text(text: str) -> str:
    return " ".join(text.split()).casefold()


def _timeline_key(claim: AnswerClaim) -> tuple[object, str]:
    earliest = min(claim.citations, key=lambda item: (item.captured_at, item.record_id.hex))
    return earliest.captured_at, earliest.record_id.hex
