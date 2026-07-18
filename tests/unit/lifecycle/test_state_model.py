from datetime import UTC, datetime

from local_recall.domain.lifecycle import (
    CaptureGeneration,
    CaptureState,
    CaptureStateTransition,
    TransitionReason,
)


def test_starting_can_transition_to_stopping_before_recording() -> None:
    transition = CaptureStateTransition(
        previous=CaptureState.STARTING,
        current=CaptureState.STOPPING,
        generation=CaptureGeneration(2),
        reason=TransitionReason.USER_STOP,
        occurred_at=datetime.now(UTC),
    )

    assert transition.current is CaptureState.STOPPING


def test_startup_dependency_failure_can_fault_from_off() -> None:
    transition = CaptureStateTransition(
        previous=CaptureState.OFF,
        current=CaptureState.FAULTED,
        generation=CaptureGeneration(1),
        reason=TransitionReason.CRITICAL_FAULT,
        occurred_at=datetime.now(UTC),
    )

    assert transition.current is CaptureState.FAULTED
