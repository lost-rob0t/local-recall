import importlib
from datetime import UTC, datetime
from uuid import UUID

answering_models = importlib.import_module("local_recall.answering.models")
evidence = importlib.import_module("local_recall.answering.evidence")
retrieval = importlib.import_module("local_recall.retrieval.service")

RECORD_A = UUID("00000000-0000-0000-0000-000000000201")
RECORD_B = UUID("00000000-0000-0000-0000-000000000202")
CAPTURE_A = datetime(2026, 8, 22, 14, 0, tzinfo=UTC)
CAPTURE_B = datetime(2026, 8, 22, 14, 5, tzinfo=UTC)


def passage(
    record_id: UUID,
    captured_at: datetime,
    excerpt: str,
    score: float,
) -> object:
    return retrieval.RetrievedPassage(
        record_id=record_id,
        captured_at=captured_at,
        excerpt=excerpt,
        score=score,
        metadata_provenance=(),
        redaction_policy_revision="redaction-v3",
        redaction_finding_count=1,
    )


def batch(*passages: object) -> object:
    return retrieval.RetrievalBatch(
        query_id=UUID("00000000-0000-0000-0000-000000000299"),
        passages=passages,
        remote_provider_eligible=False,
        policy_revision="policy-v8",
    )


def test_evidence_table_uses_opaque_labels_and_filters_weak_passages() -> None:
    table = evidence.build_evidence_table(
        batch(
            passage(RECORD_A, CAPTURE_A, "Edited the design document.", 0.91),
            passage(RECORD_B, CAPTURE_B, "Opened unrelated mail.", 0.04),
        ),
        minimum_score=0.20,
    )

    assert tuple(item.label for item in table.items) == ("E1",)
    assert table.items[0].passage.record_id == RECORD_A
    assert "Edited the design document" not in repr(table)


def test_generated_observed_claim_maps_labels_to_canonical_citations() -> None:
    table = evidence.build_evidence_table(
        batch(passage(RECORD_A, CAPTURE_A, "Edited the design document.", 0.91)),
        minimum_score=0.20,
    )

    answer = evidence.parse_generated_claims(
        '{"claims":[{"kind":"observed","text":"Edited the design document.",'
        '"evidence_ids":["E1"]}]}',
        table=table,
        mode=answering_models.AnswerMode.CONCISE,
        policy_revision="policy-v8",
    )

    claim = answer.claims[0]
    assert claim.kind is answering_models.AnswerClaimKind.OBSERVED
    assert claim.citations[0].record_id == RECORD_A
    assert claim.citations[0].captured_at == CAPTURE_A


def test_generated_claim_rejects_unknown_duplicate_and_missing_evidence_labels() -> None:
    table = evidence.build_evidence_table(
        batch(passage(RECORD_A, CAPTURE_A, "Edited the design document.", 0.91)),
        minimum_score=0.20,
    )
    invalid_payloads = (
        '{"claims":[{"kind":"inference","text":"Work continued.","evidence_ids":["E9"]}]}',
        '{"claims":[{"kind":"inference","text":"Work continued.","evidence_ids":["E1","E1"]}]}',
        '{"claims":[{"kind":"inference","text":"Work continued.","evidence_ids":[]}]}',
    )

    for payload in invalid_payloads:
        try:
            evidence.parse_generated_claims(
                payload,
                table=table,
                mode=answering_models.AnswerMode.CONCISE,
                policy_revision="policy-v8",
            )
        except ValueError as exc:
            assert "generated claim evidence is invalid" in str(exc)
        else:
            raise AssertionError("expected invalid evidence failure")


def test_observed_claim_must_be_directly_supported_by_cited_excerpt() -> None:
    table = evidence.build_evidence_table(
        batch(passage(RECORD_A, CAPTURE_A, "Edited the design document.", 0.91)),
        minimum_score=0.20,
    )

    try:
        evidence.parse_generated_claims(
            '{"claims":[{"kind":"observed","text":"Deployed the service.","evidence_ids":["E1"]}]}',
            table=table,
            mode=answering_models.AnswerMode.CONCISE,
            policy_revision="policy-v8",
        )
    except ValueError as exc:
        assert "observed claim is unsupported" in str(exc)
    else:
        raise AssertionError("expected unsupported observed claim failure")


def test_generated_schema_is_closed_and_timeline_is_chronological() -> None:
    table = evidence.build_evidence_table(
        batch(
            passage(RECORD_B, CAPTURE_B, "Ran the test suite.", 0.93),
            passage(RECORD_A, CAPTURE_A, "Edited the design document.", 0.91),
        ),
        minimum_score=0.20,
    )

    answer = evidence.parse_generated_claims(
        '{"claims":['
        '{"kind":"observed","text":"Ran the test suite.","evidence_ids":["E1"]},'
        '{"kind":"observed","text":"Edited the design document.","evidence_ids":["E2"]}'
        "]}",
        table=table,
        mode=answering_models.AnswerMode.TIMELINE,
        policy_revision="policy-v8",
    )
    assert tuple(claim.citations[0].record_id for claim in answer.claims) == (
        RECORD_A,
        RECORD_B,
    )

    try:
        evidence.parse_generated_claims(
            '{"claims":[{"kind":"inference","text":"Work continued.",'
            '"evidence_ids":["E1"],"extra":"nope"}]}',
            table=table,
            mode=answering_models.AnswerMode.CONCISE,
            policy_revision="policy-v8",
        )
    except ValueError as exc:
        assert "generated claim schema is invalid" in str(exc)
    else:
        raise AssertionError("expected closed-schema failure")
