from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from local_recall import answering


RECORD_A = UUID("00000000-0000-0000-0000-000000000101")
RECORD_B = UUID("00000000-0000-0000-0000-000000000102")
CAPTURE_A = datetime(2026, 8, 15, 14, 0, tzinfo=UTC)
CAPTURE_B = datetime(2026, 8, 15, 14, 5, tzinfo=UTC)


def citation(
    record_id: UUID = RECORD_A,
    captured_at: datetime = CAPTURE_A,
) -> answering.models.AnswerCitation:
    return answering.models.AnswerCitation(record_id=record_id, captured_at=captured_at)


def test_claim_requires_canonical_citation() -> None:
    claim = answering.models.AnswerClaim(
        kind=answering.models.AnswerClaimKind.OBSERVED,
        text="Edited the design document.",
        citations=(citation(),),
    )

    assert claim.kind is answering.models.AnswerClaimKind.OBSERVED
    assert claim.citations[0].record_id == RECORD_A
    assert "Edited the design document" not in repr(claim)


def test_claim_rejects_duplicate_citations() -> None:
    with pytest.raises(ValueError, match="citations must be unique"):
        answering.models.AnswerClaim(
            kind=answering.models.AnswerClaimKind.INFERENCE,
            text="The records suggest design work continued.",
            citations=(citation(), citation()),
        )


def test_claim_rejects_empty_citations_and_text() -> None:
    with pytest.raises(ValueError, match="citations must not be empty"):
        answering.models.AnswerClaim(
            kind=answering.models.AnswerClaimKind.OBSERVED,
            text="Edited the design document.",
            citations=(),
        )

    with pytest.raises(ValueError, match="text must not be empty"):
        answering.models.AnswerClaim(
            kind=answering.models.AnswerClaimKind.OBSERVED,
            text="   ",
            citations=(citation(),),
        )


def test_citation_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="captured_at must be timezone-aware"):
        answering.models.AnswerCitation(
            record_id=RECORD_A,
            captured_at=datetime(2026, 8, 15, 14, 0),
        )


def test_cited_answer_preserves_claim_order_and_hides_content_from_repr() -> None:
    answer = answering.models.CitedAnswer(
        mode=answering.models.AnswerMode.TIMELINE,
        claims=(
            answering.models.AnswerClaim(
                kind=answering.models.AnswerClaimKind.OBSERVED,
                text="Edited the design document.",
                citations=(citation(),),
            ),
            answering.models.AnswerClaim(
                kind=answering.models.AnswerClaimKind.INFERENCE,
                text="The records suggest the task continued.",
                citations=(citation(RECORD_B, CAPTURE_B),),
            ),
        ),
        insufficient_evidence=False,
        policy_revision="policy-v7",
    )

    assert tuple(item.kind for item in answer.claims) == (
        answering.models.AnswerClaimKind.OBSERVED,
        answering.models.AnswerClaimKind.INFERENCE,
    )
    rendered = repr(answer)
    assert "design document" not in rendered
    assert "task continued" not in rendered
    assert "claim_count=2" in rendered


def test_cited_answer_rejects_inconsistent_evidence_state() -> None:
    claim = answering.models.AnswerClaim(
        kind=answering.models.AnswerClaimKind.OBSERVED,
        text="Edited the design document.",
        citations=(citation(),),
    )

    with pytest.raises(ValueError, match="insufficient answer cannot contain claims"):
        answering.models.CitedAnswer(
            mode=answering.models.AnswerMode.CONCISE,
            claims=(claim,),
            insufficient_evidence=True,
            policy_revision="policy-v7",
        )

    with pytest.raises(ValueError, match="supported answer must contain claims"):
        answering.models.CitedAnswer(
            mode=answering.models.AnswerMode.CONCISE,
            claims=(),
            insufficient_evidence=False,
            policy_revision="policy-v7",
        )
