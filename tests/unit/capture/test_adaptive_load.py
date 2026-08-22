from __future__ import annotations

from local_recall import domain
from local_recall.capture import adaptive


def _context(index: int) -> adaptive.DedupContext:
    return adaptive.DedupContext(
        generation=domain.CaptureGeneration(7),
        policy_revision="policy-a",
        configuration_revision="config-a",
        application="editor",
        workspace=f"workspace-{index}",
        window_id=str(index),
    )


def test_high_frequency_context_churn_keeps_only_constant_controller_state() -> None:
    controller = adaptive.AdaptiveCaptureController(
        cadence_seconds=3600.0,
        change_threshold=0.02,
        debounce_seconds=60.0,
    )
    initial = _context(0)
    controller.mark_capture_started(context=initial, now_monotonic_ns=0)
    controller.classify_frame(
        context=initial,
        fingerprint=0,
        observed_at_monotonic_ns=0,
    )

    for index in range(1, 10_001):
        now = index * 1_000_000
        context = _context(index)
        controller.poll(context=context, now_monotonic_ns=now)
        controller.classify_frame(
            context=context,
            fingerprint=index,
            observed_at_monotonic_ns=now,
        )

    rendered = repr(controller)
    assert controller.pending_change_count == 1
    assert len(rendered) < 200
    assert "workspace-10000" not in rendered
    assert "9999" not in rendered
