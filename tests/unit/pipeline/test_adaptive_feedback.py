from __future__ import annotations

from uuid import UUID

from local_recall.capture.adaptive import AdaptiveCaptureController
from local_recall.pipeline.models import SubmissionResult, SubmissionStatus
from local_recall.pipeline.runtime import apply_submission_feedback


def _controller() -> AdaptiveCaptureController:
    return AdaptiveCaptureController(
        cadence_seconds=10.0,
        change_threshold=0.02,
        debounce_seconds=0.25,
        max_backoff_multiplier=8,
    )


def _result(status: SubmissionStatus) -> SubmissionResult:
    return SubmissionResult(record_id=UUID(int=1), status=status)


def test_pipeline_drop_and_coalesce_back_off_capture_without_adding_queue_state() -> None:
    controller = _controller()

    apply_submission_feedback(controller, _result(SubmissionStatus.DROPPED))
    assert controller.effective_cadence_seconds == 20.0

    apply_submission_feedback(controller, _result(SubmissionStatus.COALESCED))
    assert controller.effective_cadence_seconds == 40.0
    assert controller.pending_change_count == 0


def test_pipeline_acceptance_recovers_toward_base_cadence() -> None:
    controller = _controller()
    apply_submission_feedback(controller, _result(SubmissionStatus.DROPPED))
    apply_submission_feedback(controller, _result(SubmissionStatus.DROPPED))

    apply_submission_feedback(controller, _result(SubmissionStatus.ACCEPTED))
    assert controller.effective_cadence_seconds == 20.0

    apply_submission_feedback(controller, _result(SubmissionStatus.ACCEPTED))
    assert controller.effective_cadence_seconds == 10.0
