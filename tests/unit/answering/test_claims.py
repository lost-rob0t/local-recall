from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from local_recall.answering.models import (
    AnswerCitation,
    AnswerClaim,
    AnswerClaimKind,
    AnswerMode,
    CitedAnswer,
)


RECORD_A = UUID("00000000-0000-0000-0000-000000000101")
RECORD_B = UUID("00000000-0000-0000-0000-000000000102")
CAPTURE_A = datetime(2026, 8, 15, 14, 0, tzinfo=UTC)
CAPTURE_B = datetime(2026, 8, 15, 14, 5, tzinfo=UTC)


def citation(record_id: UUID = RECORD_A, captured_at: datetime = CAPTURE_A) -> AnswerCitation:
    return AnswerCitation(record_id=record_id, captured_at=captured_at)


def assert_value_error(callable_: Callable[[], None], expected: str) -> None:
    try:
        callable_()
    except ValueError as exc:
        assert expected in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_claim_requires_canonical_citation() -> None:
    claim = AnswerClaim(
        kind=AnswerClaimKind.OBSERVED,
        text="Edited the design document.",
        citations=(citation(),),
    )

    assert claim.kind is AnswerClaimKind.OBSERVED
    assert claim.citations[0].record_id == RECORD_A
    assert "Edited the design document" not in repr(claim)


def test_claim_rejects_duplicate_citations() -> None:
    def construct() -> None:
        AnswerClaim(
            kind=AnswerClaimKind.INFERENCE,
            text="The records suggest design work continued.",
            citations=(citation(), citation()),
        )

    assert_value_error(construct, "citations must be unique")


def test_cited_answer_preserves_claim_order_and_hides_content_from_repr() -> None:
    answer = CitedAnswer(
        mode=AnswerMode.TIMELINE,
        claims=(
            AnswerClaim(
                kind=AnswerClaimKind.OBSERVED,
                text="Edited the design document.",
                citations=(citation(),),
            ),
            AnswerClaim(
                kind=AnswerClaimKind.INFERENCE,
                text="The records suggest the task continued.",
                citations=(citation(RECORD_B, CAPTURE_B),),
            ),
        ),
        insufficient_evidence=False,
        policy_revision="policy-v7",
    )

    assert tuple(item.kind for item in answer.claims) == (
        AnswerClaimKind.OBSERVED,
        AnswerClaimKind.INFERENCE,
    )
    rendered = repr(answer)
    assert "design document" not in rendered
    assert "task continued" not in rendered
    assert "claim_count=2" in rendered


def test_cited_answer_rejects_claims_when_marked_insufficient() -> None:
    def construct() -> None:
        CitedAnswer(
            mode=AnswerMode.CONCISE,
            claims=(
                AnswerClaim(
                    kind=AnswerClaimKind.OBSERVED,
                    text="Edited the design document.",
                    citations=(citation(),),
                ),
            ),
            insufficient_evidence=True,
            policy_revision="policy-v7",
        )

    assert_value_error(construct, "insufficient answer cannot contain claims")
