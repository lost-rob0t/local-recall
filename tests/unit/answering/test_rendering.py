import importlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from local_recall.activity.clustering import ActivityCluster
from local_recall.answering.models import (
    AnswerCitation,
    AnswerClaim,
    AnswerClaimKind,
    AnswerMode,
    CitedAnswer,
)

RECORD_A = UUID("00000000-0000-0000-0000-000000000401")
RECORD_B = UUID("00000000-0000-0000-0000-000000000402")
CAPTURE_A = datetime(2026, 8, 15, 14, 0, tzinfo=UTC)
CAPTURE_B = datetime(2026, 8, 15, 14, 5, tzinfo=UTC)


def render_answer(answer: CitedAnswer, *, clusters: tuple[ActivityCluster, ...]) -> str:
    module = importlib.import_module("local_recall.answering.rendering")
    renderer = cast(Callable[..., str], module.__dict__["render_answer"])
    return renderer(answer, clusters=clusters)


def answer(mode: AnswerMode) -> CitedAnswer:
    return CitedAnswer(
        mode=mode,
        claims=(
            AnswerClaim(
                kind=AnswerClaimKind.OBSERVED,
                text="Edited the design document.",
                citations=(AnswerCitation(record_id=RECORD_A, captured_at=CAPTURE_A),),
            ),
            AnswerClaim(
                kind=AnswerClaimKind.INFERENCE,
                text="The evidence suggests the design task continued.",
                citations=(AnswerCitation(record_id=RECORD_B, captured_at=CAPTURE_B),),
            ),
        ),
        insufficient_evidence=False,
        policy_revision="policy-v8",
    )


def cluster() -> ActivityCluster:
    return ActivityCluster(
        source_record_ids=(RECORD_A, RECORD_B),
        started_at=CAPTURE_A,
        ended_at=CAPTURE_B,
    )


def test_concise_rendering_marks_claim_kind_and_cites_record_timestamp_and_activity() -> None:
    rendered = render_answer(answer(AnswerMode.CONCISE), clusters=(cluster(),))

    assert "Observed: Edited the design document." in rendered
    assert "Inference: The evidence suggests the design task continued." in rendered
    assert str(RECORD_A) in rendered
    assert CAPTURE_A.isoformat() in rendered
    assert f"activity {CAPTURE_A.isoformat()}..{CAPTURE_B.isoformat()}" in rendered


def test_timeline_rendering_orders_claims_by_canonical_capture_time() -> None:
    original = answer(AnswerMode.TIMELINE)
    reversed_answer = CitedAnswer(
        mode=AnswerMode.TIMELINE,
        claims=tuple(reversed(original.claims)),
        insufficient_evidence=False,
        policy_revision=original.policy_revision,
    )

    rendered = render_answer(reversed_answer, clusters=(cluster(),))

    assert rendered.index(CAPTURE_A.isoformat()) < rendered.index(CAPTURE_B.isoformat())


def test_deleted_or_stale_cluster_falls_back_to_record_timestamp_citation() -> None:
    rendered = render_answer(answer(AnswerMode.CONCISE), clusters=())

    assert str(RECORD_A) in rendered
    assert CAPTURE_A.isoformat() in rendered
    assert "activity " not in rendered


def test_insufficient_evidence_is_explicit_and_contains_no_citation() -> None:
    insufficient = CitedAnswer(
        mode=AnswerMode.CONCISE,
        claims=(),
        insufficient_evidence=True,
        policy_revision="policy-v8",
    )

    rendered = render_answer(insufficient, clusters=())

    assert rendered == "Insufficient evidence."
    assert "record " not in rendered
