from datetime import UTC, datetime

import pytest

from local_recall.domain.lifecycle import (
    CaptureGeneration,
    CaptureState,
    CaptureStateTransition,
    TransitionReason,
)


def test_capture_generation_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        CaptureGeneration(0)


def test_lifecycle_transition_accepts_valid_edge() -> None:
    transition = CaptureStateTransition(
        previous=CaptureState.OFF,
        current=CaptureState.STARTING,
        generation=CaptureGeneration(1),
        reason=TransitionReason.USER_START,
        occurred_at=datetime.now(UTC),
    )

    assert transition.current is CaptureState.STARTING


def test_lifecycle_transition_rejects_invalid_edge() -> None:
    with pytest.raises(ValueError, match="invalid capture transition"):
        CaptureStateTransition(
            previous=CaptureState.OFF,
            current=CaptureState.RECORDING,
            generation=CaptureGeneration(1),
            reason=TransitionReason.USER_START,
            occurred_at=datetime.now(UTC),
        )


def test_lifecycle_transition_requires_timezone() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        CaptureStateTransition(
            previous=CaptureState.OFF,
            current=CaptureState.STARTING,
            generation=CaptureGeneration(1),
            reason=TransitionReason.USER_START,
            occurred_at=datetime.now(),
        )
