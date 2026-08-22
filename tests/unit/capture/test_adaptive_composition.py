from __future__ import annotations

from local_recall.capture.composition import build_adaptive_capture_controller
from local_recall.config.models import CaptureSettings


def test_adaptive_controller_uses_validated_capture_settings() -> None:
    controller = build_adaptive_capture_controller(
        CaptureSettings(cadence_seconds=7.5, change_threshold=0.125)
    )

    assert controller.base_cadence_seconds == 7.5
    assert controller.change_threshold == 0.125
    assert controller.effective_cadence_seconds == 7.5
