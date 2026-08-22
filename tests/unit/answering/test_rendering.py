from datetime import UTC, datetime
from uuid import UUID

import local_recall.activity.clustering
import local_recall.answering.models
import local_recall.answering.rendering

clustering = local_recall.activity.clustering
models = local_recall.answering.models
rendering = local_recall.answering.rendering

RECORD_A = UUID("00000000-0000-0000-0000-000000000401")
RECORD_B = UUID("00000000-0000-0000-0000-000000000402")
CAPTURE_A = datetime(2026, 8, 15, 14, 0, tzinfo=UTC)
CAPTURE_B = datetime(2026, 8, 15, 14, 5, tzinfo=UTC)


def answer(mode: models.AnswerMode) -> models.CitedAnswer:
    return models.CitedAnswer(
        mode=mode,
        claims=(
            models.AnswerClaim(
                kind=models.AnswerClaimKind.OBSERVED,
                text="Edited the design document.",
                citations=(models.AnswerCitation(record_id=RECORD_A, captured_at=CAPTURE_A),),
            ),
            models.AnswerClaim(
                kind=models.AnswerClaimKind.INFERENCE,
                text="The evidence suggests the design task continued.",
                citations=(models.AnswerCitation(record_id=RECORD_B, captured_at=CAPTURE_B),),
            ),
        ),
        insufficient_evidence=False,
        policy_revision="policy-v8",
    )


def cluster() -> clustering.ActivityCluster:
    return clustering.ActivityCluster(
        source_record_ids=(RECORD_A, RECORD_B),
        started_at=CAPTURE_A,
        ended_at=CAPTURE_B,
    )


def test_concise_rendering_marks_claim_kind_and_cites_record_timestamp_and_activity() -> None:
    rendered = rendering.render_answer(answer(models.AnswerMode.CONCISE), clusters=(cluster(),))

    assert "Observed: Edited the design document." in rendered
    assert "Inference: The evidence suggests the design task continued." in rendered
    assert str(RECORD_A) in rendered
    assert CAPTURE_A.isoformat() in rendered
    assert f"activity {CAPTURE_A.isoformat()}..{CAPTURE_B.isoformat()}" in rendered


def test_timeline_rendering_orders_claims_by_canonical_capture_time() -> None:
    original = answer(models.AnswerMode.TIMELINE)
    reversed_answer = models.CitedAnswer(
        mode=models.AnswerMode.TIMELINE,
        claims=tuple(reversed(original.claims)),
        insufficient_evidence=False,
        policy_revision=original.policy_revision,
    )

    rendered = rendering.render_answer(reversed_answer, clusters=(cluster(),))

    assert rendered.index(CAPTURE_A.isoformat()) < rendered.index(CAPTURE_B.isoformat())


def test_deleted_or_stale_cluster_falls_back_to_record_timestamp_citation() -> None:
    rendered = rendering.render_answer(answer(models.AnswerMode.CONCISE), clusters=())

    assert str(RECORD_A) in rendered
    assert CAPTURE_A.isoformat() in rendered
    assert "activity " not in rendered


def test_insufficient_evidence_is_explicit_and_contains_no_citation() -> None:
    insufficient = models.CitedAnswer(
        mode=models.AnswerMode.CONCISE,
        claims=(),
        insufficient_evidence=True,
        policy_revision="policy-v8",
    )

    rendered = rendering.render_answer(insufficient, clusters=())

    assert rendered == "Insufficient evidence."
    assert "record " not in rendered
