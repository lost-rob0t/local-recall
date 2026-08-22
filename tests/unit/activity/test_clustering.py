from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from local_recall.activity.clustering import (
    ActivityClusteringPolicy,
    ActivityRecordFeatures,
    ActivitySegmenter,
)


def _id(value: int) -> UUID:
    return UUID(int=value)


def _feature(
    value: int,
    at: datetime,
    *,
    application: str | None = "emacs",
    workspace: str | None = "dev",
    policy_revision: str = "policy-v1",
    perceptual_hash: int | None = 0,
    semantic_vector: tuple[float, ...] | None = (1.0, 0.0),
) -> ActivityRecordFeatures:
    return ActivityRecordFeatures(
        record_id=_id(value),
        captured_at=at,
        policy_revision=policy_revision,
        application=application,
        workspace=workspace,
        perceptual_hash=perceptual_hash,
        semantic_vector=semantic_vector,
    )


def _segmenter() -> ActivitySegmenter:
    return ActivitySegmenter(
        ActivityClusteringPolicy(
            max_gap_seconds=300.0,
            strong_gap_seconds=30.0,
            minimum_continuity_score=0.55,
            minimum_semantic_similarity=0.75,
        )
    )


def test_repetitive_adjacent_records_form_one_ordered_activity_span() -> None:
    start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    records = (
        _feature(3, start + timedelta(seconds=20)),
        _feature(1, start),
        _feature(2, start + timedelta(seconds=10)),
    )

    clusters = _segmenter().segment(records)

    assert len(clusters) == 1
    assert clusters[0].source_record_ids == (_id(1), _id(2), _id(3))
    assert clusters[0].started_at == start
    assert clusters[0].ended_at == start + timedelta(seconds=20)


def test_long_idle_gap_is_a_hard_boundary_even_for_identical_content() -> None:
    start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    clusters = _segmenter().segment(
        (
            _feature(1, start),
            _feature(2, start + timedelta(minutes=6)),
        )
    )

    assert tuple(cluster.source_record_ids for cluster in clusters) == ((_id(1),), (_id(2),))


def test_workspace_change_is_a_hard_boundary() -> None:
    start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    clusters = _segmenter().segment(
        (
            _feature(1, start, workspace="dev"),
            _feature(2, start + timedelta(seconds=5), workspace="chat"),
        )
    )

    assert tuple(cluster.source_record_ids for cluster in clusters) == ((_id(1),), (_id(2),))


def test_short_cross_application_hop_can_remain_one_activity_with_strong_evidence() -> None:
    start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    clusters = _segmenter().segment(
        (
            _feature(1, start, application="emacs", perceptual_hash=0),
            _feature(
                2,
                start + timedelta(seconds=4),
                application="firefox",
                perceptual_hash=0,
                semantic_vector=(0.99, 0.01),
            ),
            _feature(
                3,
                start + timedelta(seconds=8),
                application="emacs",
                perceptual_hash=0,
                semantic_vector=(0.98, 0.02),
            ),
        )
    )

    assert len(clusters) == 1
    assert clusters[0].source_record_ids == (_id(1), _id(2), _id(3))


def test_same_application_different_semantic_task_splits_conservatively() -> None:
    start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    clusters = _segmenter().segment(
        (
            _feature(1, start, semantic_vector=(1.0, 0.0), perceptual_hash=0),
            _feature(
                2,
                start + timedelta(seconds=5),
                semantic_vector=(0.0, 1.0),
                perceptual_hash=0,
            ),
        )
    )

    assert tuple(cluster.source_record_ids for cluster in clusters) == ((_id(1),), (_id(2),))


def test_low_confidence_pair_splits_when_similarity_evidence_is_missing() -> None:
    start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    clusters = _segmenter().segment(
        (
            _feature(1, start, perceptual_hash=None, semantic_vector=None),
            _feature(
                2,
                start + timedelta(seconds=5),
                perceptual_hash=None,
                semantic_vector=None,
            ),
        )
    )

    assert tuple(cluster.source_record_ids for cluster in clusters) == ((_id(1),), (_id(2),))


def test_redaction_policy_revision_change_is_a_hard_boundary() -> None:
    start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    clusters = _segmenter().segment(
        (
            _feature(1, start, policy_revision="policy-v1"),
            _feature(2, start + timedelta(seconds=5), policy_revision="policy-v2"),
        )
    )

    assert tuple(cluster.source_record_ids for cluster in clusters) == ((_id(1),), (_id(2),))


def test_equal_timestamps_use_record_id_for_deterministic_membership_order() -> None:
    at = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    clusters = _segmenter().segment((_feature(2, at), _feature(1, at)))

    assert len(clusters) == 1
    assert clusters[0].source_record_ids == (_id(1), _id(2))
