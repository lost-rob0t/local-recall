from __future__ import annotations

from datetime import UTC, datetime
from importlib import import_module
from typing import Any
from uuid import UUID


RECORD_A = UUID("00000000-0000-0000-0000-000000000101")
RECORD_B = UUID("00000000-0000-0000-0000-000000000102")
CAPTURE_A = datetime(2026, 8, 15, 14, 0, tzinfo=UTC)
CAPTURE_B = datetime(2026, 8, 15, 14, 5, tzinfo=UTC)
MODELS: Any = import_module("local_recall.answering.models")


def citation(record_id: UUID = RECORD_A, captured_at: datetime = CAPTURE_A) -> Any:
    return MODELS.AnswerCitation(record_id=record_id, captured_at=captured_at)


def expect_value_error(callable_: Any, expected: str) -> None:
    try:
        callable_()
    except ValueError as exc:
        assert expected in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_claim_requires_canonical_citation() -> None:
    claim = MODELS.AnswerClaim(
        kind=MODELS.AnswerClaimKind.OBSERVED,
        text="Edited the design document.",
        citations=(citation(),),
    )

    assert claim.kind is MODELS.AnswerClaimKind.OBSERVED
    assert claim.citations[0].record_id == RECORD_A
    assert "Edited the design document" not in repr(claim)


def test_claim_rejects_duplicate_citations() -> None:
    def construct() -> None:
        MODELS.AnswerClaim(
            kind=MODELS.AnswerClaimKind.INFERENCE,
            text="The records suggest design work continued.",
            citations=(citation(), citation()),
        )

    expect_value_error(construct, "citations must be unique")


def test_claim_rejects_empty_citations_and_text() -> None:
    def empty_citations() -> None:
        MODELS.AnswerClaim(
            kind=MODELS.AnswerClaimKind.OBSERVED,
            text="Edited the design document.",
            citations=(),
        )

    def empty_text() -> None:
        MODELS.AnswerClaim(
            kind=MODELS.AnswerClaimKind.OBSERVED,
            text="   ",
            citations=(citation(),),
        )

    expect_value_error(empty_citations, "citations must not be empty")
    expect_value_error(empty_text, "text must not be empty")


def test_citation_requires_timezone_aware_timestamp() -> None:
    def construct() -> None:
        MODELS.AnswerCitation(
            record_id=RECORD_A,
            captured_at=datetime(2026, 8, 15, 14, 0),
        )

    expect_value_error(construct, "captured_at must be timezone-aware")


def test_cited_answer_preserves_claim_order_and_hides_content_from_repr() -> None:
    answer = MODELS.CitedAnswer(
        mode=MODELS.AnswerMode.TIMELINE,
        claims=(
            MODELS.AnswerClaim(
                kind=MODELS.AnswerClaimKind.OBSERVED,
                text="Edited the design document.",
                citations=(citation(),),
            ),
            MODELS.AnswerClaim(
                kind=MODELS.AnswerClaimKind.INFERENCE,
                text="The records suggest the task continued.",
                citations=(citation(RECORD_B, CAPTURE_B),),
            ),
        ),
        insufficient_evidence=False,
        policy_revision="policy-v7",
    )

    assert tuple(item.kind for item in answer.claims) == (
        MODELS.AnswerClaimKind.OBSERVED,
        MODELS.AnswerClaimKind.INFERENCE,
    )
    rendered = repr(answer)
    assert "design document" not in rendered
    assert "task continued" not in rendered
    assert "claim_count=2" in rendered


def test_cited_answer_rejects_inconsistent_evidence_state() -> None:
    claim = MODELS.AnswerClaim(
        kind=MODELS.AnswerClaimKind.OBSERVED,
        text="Edited the design document.",
        citations=(citation(),),
    )

    def insufficient_with_claims() -> None:
        MODELS.CitedAnswer(
            mode=MODELS.AnswerMode.CONCISE,
            claims=(claim,),
            insufficient_evidence=True,
            policy_revision="policy-v7",
        )

    def supported_without_claims() -> None:
        MODELS.CitedAnswer(
            mode=MODELS.AnswerMode.CONCISE,
            claims=(),
            insufficient_evidence=False,
            policy_revision="policy-v7",
        )

    expect_value_error(insufficient_with_claims, "insufficient answer cannot contain claims")
    expect_value_error(supported_without_claims, "supported answer must contain claims")
