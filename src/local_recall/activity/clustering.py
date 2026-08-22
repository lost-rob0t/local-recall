from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from local_recall.domain._validation import require_aware, require_nonempty

_HASH_BITS = 64
_MAX_CONTEXT_LENGTH = 4096
_MAX_POLICY_REVISION_LENGTH = 256
_MAX_VECTOR_DIMENSIONS = 16_384


@dataclass(frozen=True, slots=True, repr=False)
class ActivityRecordFeatures:
    record_id: UUID
    captured_at: datetime
    policy_revision: str
    application: str | None = None
    workspace: str | None = None
    perceptual_hash: int | None = None
    semantic_vector: tuple[float, ...] | None = None

    def __post_init__(self) -> None:
        require_aware(self.captured_at, "captured_at")
        require_nonempty(self.policy_revision, "policy_revision")
        if len(self.policy_revision) > _MAX_POLICY_REVISION_LENGTH:
            raise ValueError("policy_revision exceeds maximum length")
        for name, value in (("application", self.application), ("workspace", self.workspace)):
            if value is not None:
                require_nonempty(value, name)
                if len(value) > _MAX_CONTEXT_LENGTH:
                    raise ValueError(f"{name} exceeds maximum length")
        if self.perceptual_hash is not None and not 0 <= self.perceptual_hash < 1 << _HASH_BITS:
            raise ValueError("perceptual_hash must be an unsigned 64-bit integer")
        if self.semantic_vector is not None:
            if not self.semantic_vector:
                raise ValueError("semantic_vector must not be empty")
            if len(self.semantic_vector) > _MAX_VECTOR_DIMENSIONS:
                raise ValueError("semantic_vector exceeds maximum dimensions")
            if any(not math.isfinite(value) for value in self.semantic_vector):
                raise ValueError("semantic_vector values must be finite")

    def __repr__(self) -> str:
        return (
            "ActivityRecordFeatures("
            f"record_id={self.record_id!r}, captured_at={self.captured_at!r}, "
            f"has_application={self.application is not None}, "
            f"has_workspace={self.workspace is not None}, "
            f"has_perceptual_hash={self.perceptual_hash is not None}, "
            f"has_semantic_vector={self.semantic_vector is not None})"
        )


@dataclass(frozen=True, slots=True)
class ActivityClusteringPolicy:
    max_gap_seconds: float
    strong_gap_seconds: float
    minimum_continuity_score: float
    minimum_semantic_similarity: float

    def __post_init__(self) -> None:
        for name, value in (
            ("max_gap_seconds", self.max_gap_seconds),
            ("strong_gap_seconds", self.strong_gap_seconds),
            ("minimum_continuity_score", self.minimum_continuity_score),
            ("minimum_semantic_similarity", self.minimum_semantic_similarity),
        ):
            if not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
        if not 0.0 < self.max_gap_seconds <= 86_400.0:
            raise ValueError("max_gap_seconds must be in (0, 86400]")
        if not 0.0 <= self.strong_gap_seconds <= self.max_gap_seconds:
            raise ValueError("strong_gap_seconds must be in [0, max_gap_seconds]")
        if not 0.0 <= self.minimum_continuity_score <= 1.0:
            raise ValueError("minimum_continuity_score must be in [0, 1]")
        if not 0.0 <= self.minimum_semantic_similarity <= 1.0:
            raise ValueError("minimum_semantic_similarity must be in [0, 1]")


@dataclass(frozen=True, slots=True)
class ActivityCluster:
    source_record_ids: tuple[UUID, ...]
    started_at: datetime
    ended_at: datetime

    def __post_init__(self) -> None:
        if not self.source_record_ids:
            raise ValueError("activity cluster requires source records")
        if len(set(self.source_record_ids)) != len(self.source_record_ids):
            raise ValueError("activity cluster source records must be unique")
        require_aware(self.started_at, "started_at")
        require_aware(self.ended_at, "ended_at")
        if self.ended_at < self.started_at:
            raise ValueError("activity cluster end precedes start")


class ActivitySegmenter:
    __slots__ = ("_policy",)

    def __init__(self, policy: ActivityClusteringPolicy) -> None:
        self._policy = policy

    def segment(self, records: tuple[ActivityRecordFeatures, ...]) -> tuple[ActivityCluster, ...]:
        if not records:
            return ()
        ordered = tuple(sorted(records, key=lambda item: (item.captured_at, str(item.record_id))))
        groups: list[list[ActivityRecordFeatures]] = [[ordered[0]]]
        for current in ordered[1:]:
            previous = groups[-1][-1]
            if self._continues(previous, current):
                groups[-1].append(current)
            else:
                groups.append([current])
        return tuple(_cluster(group) for group in groups)

    def _continues(self, previous: ActivityRecordFeatures, current: ActivityRecordFeatures) -> bool:
        if previous.policy_revision != current.policy_revision:
            return False
        gap = (current.captured_at - previous.captured_at).total_seconds()
        if gap < 0.0:
            raise ValueError("activity records are not time ordered")
        if gap > self._policy.max_gap_seconds:
            return False
        if (
            previous.workspace is not None
            and current.workspace is not None
            and previous.workspace != current.workspace
        ):
            return False

        semantic = _semantic_similarity(previous.semantic_vector, current.semantic_vector)
        if semantic is None or semantic < self._policy.minimum_semantic_similarity:
            return False
        perceptual = _perceptual_similarity(previous.perceptual_hash, current.perceptual_hash)
        if perceptual is None:
            return False

        score = 0.4 * semantic + 0.2 * perceptual
        if gap <= self._policy.strong_gap_seconds:
            score += 0.2
        elif self._policy.max_gap_seconds > self._policy.strong_gap_seconds:
            remaining = self._policy.max_gap_seconds - gap
            window = self._policy.max_gap_seconds - self._policy.strong_gap_seconds
            score += 0.2 * max(0.0, remaining / window)
        if (
            previous.application is not None
            and current.application is not None
            and previous.application == current.application
        ):
            score += 0.2
        return score >= self._policy.minimum_continuity_score


def _cluster(records: list[ActivityRecordFeatures]) -> ActivityCluster:
    first = records[0]
    last = records[-1]
    return ActivityCluster(
        source_record_ids=tuple(item.record_id for item in records),
        started_at=first.captured_at,
        ended_at=last.captured_at,
    )


def _perceptual_similarity(left: int | None, right: int | None) -> float | None:
    if left is None or right is None:
        return None
    return 1.0 - (left ^ right).bit_count() / _HASH_BITS


def _semantic_similarity(
    left: tuple[float, ...] | None,
    right: tuple[float, ...] | None,
) -> float | None:
    if left is None or right is None:
        return None
    if len(left) != len(right):
        raise ValueError("semantic vectors must have equal dimensions")
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return max(0.0, min(1.0, numerator / (left_norm * right_norm)))
