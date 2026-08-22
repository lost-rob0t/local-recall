import local_recall.answering.models as answering_models


RECORD_A = answering_models.UUID("00000000-0000-0000-0000-000000000101")
RECORD_B = answering_models.UUID("00000000-0000-0000-0000-000000000102")
CAPTURE_A = answering_models.datetime.fromisoformat("2026-08-15T14:00:00+00:00")
CAPTURE_B = answering_models.datetime.fromisoformat("2026-08-15T14:05:00+00:00")


def citation(
    record_id: answering_models.UUID = RECORD_A,
    captured_at: answering_models.datetime = CAPTURE_A,
) -> answering_models.AnswerCitation:
    return answering_models.AnswerCitation(record_id=record_id, captured_at=captured_at)


def expect_value_error(callable_: object, expected: str) -> None:
    if not callable(callable_):
        raise TypeError("test helper requires a callable")
    try:
        callable_()
    except ValueError as exc:
        if expected not in str(exc):
            raise AssertionError(f"missing expected error fragment: {expected}") from exc
    else:
        raise AssertionError("expected ValueError")


def test_claim_requires_canonical_citation() -> None:
    claim = answering_models.AnswerClaim(
        kind=answering_models.AnswerClaimKind.OBSERVED,
        text="Edited the design document.",
        citations=(citation(),),
    )

    assert claim.kind is answering_models.AnswerClaimKind.OBSERVED
    assert claim.citations[0].record_id == RECORD_A
    assert "Edited the design document" not in repr(claim)


def test_claim_rejects_duplicate_citations() -> None:
    def construct() -> None:
        answering_models.AnswerClaim(
            kind=answering_models.AnswerClaimKind.INFERENCE,
            text="The records suggest design work continued.",
            citations=(citation(), citation()),
        )

    expect_value_error(construct, "citations must be unique")


def test_claim_rejects_empty_citations_and_text() -> None:
    def empty_citations() -> None:
        answering_models.AnswerClaim(
            kind=answering_models.AnswerClaimKind.OBSERVED,
            text="Edited the design document.",
            citations=(),
        )

    def empty_text() -> None:
        answering_models.AnswerClaim(
            kind=answering_models.AnswerClaimKind.OBSERVED,
            text="   ",
            citations=(citation(),),
        )

    expect_value_error(empty_citations, "citations must not be empty")
    expect_value_error(empty_text, "text must not be empty")


def test_citation_requires_timezone_aware_timestamp() -> None:
    def construct() -> None:
        answering_models.AnswerCitation(
            record_id=RECORD_A,
            captured_at=answering_models.datetime(2026, 8, 15, 14, 0),
        )

    expect_value_error(construct, "captured_at must be timezone-aware")


def test_cited_answer_preserves_claim_order_and_hides_content_from_repr() -> None:
    answer = answering_models.CitedAnswer(
        mode=answering_models.AnswerMode.TIMELINE,
        claims=(
            answering_models.AnswerClaim(
                kind=answering_models.AnswerClaimKind.OBSERVED,
                text="Edited the design document.",
                citations=(citation(),),
            ),
            answering_models.AnswerClaim(
                kind=answering_models.AnswerClaimKind.INFERENCE,
                text="The records suggest the task continued.",
                citations=(citation(RECORD_B, CAPTURE_B),),
            ),
        ),
        insufficient_evidence=False,
        policy_revision="policy-v7",
    )

    assert tuple(item.kind for item in answer.claims) == (
        answering_models.AnswerClaimKind.OBSERVED,
        answering_models.AnswerClaimKind.INFERENCE,
    )
    rendered = repr(answer)
    assert "design document" not in rendered
    assert "task continued" not in rendered
    assert "claim_count=2" in rendered


def test_cited_answer_rejects_inconsistent_evidence_state() -> None:
    claim = answering_models.AnswerClaim(
        kind=answering_models.AnswerClaimKind.OBSERVED,
        text="Edited the design document.",
        citations=(citation(),),
    )

    def insufficient_with_claims() -> None:
        answering_models.CitedAnswer(
            mode=answering_models.AnswerMode.CONCISE,
            claims=(claim,),
            insufficient_evidence=True,
            policy_revision="policy-v7",
        )

    def supported_without_claims() -> None:
        answering_models.CitedAnswer(
            mode=answering_models.AnswerMode.CONCISE,
            claims=(),
            insufficient_evidence=False,
            policy_revision="policy-v7",
        )

    expect_value_error(insufficient_with_claims, "insufficient answer cannot contain claims")
    expect_value_error(supported_without_claims, "supported answer must contain claims")
