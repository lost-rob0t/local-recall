from __future__ import annotations

from local_recall import domain
from local_recall.capture import adaptive


def _context(
    *,
    generation: int = 7,
    policy_revision: str = "policy-a",
    configuration_revision: str = "config-a",
    application: str = "editor",
    workspace: str = "code",
    window_id: str = "41",
) -> adaptive.DedupContext:
    return adaptive.DedupContext(
        generation=domain.CaptureGeneration(generation),
        policy_revision=policy_revision,
        configuration_revision=configuration_revision,
        application=application,
        workspace=workspace,
        window_id=window_id,
    )


def _gradient_rgb(*, changed_pixel: bool = False) -> bytearray:
    width = 18
    height = 16
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            value = min(255, x * 12 + y)
            pixels.extend((value, value, value))
    if changed_pixel:
        pixels[-3:] = b"\xff\xff\xff"
    return pixels


def test_perceptual_hash_is_stable_for_tiny_rgb8_change() -> None:
    original = adaptive.perceptual_dhash_rgb8(_gradient_rgb(), width=18, height=16)
    near_duplicate = adaptive.perceptual_dhash_rgb8(
        _gradient_rgb(changed_pixel=True), width=18, height=16
    )

    assert original.bit_length() <= 64
    assert (original ^ near_duplicate).bit_count() <= 2


def test_cadence_capture_and_stable_context_do_not_create_event_queue() -> None:
    controller = adaptive.AdaptiveCaptureController(
        cadence_seconds=10.0,
        change_threshold=0.05,
        debounce_seconds=0.25,
    )
    context = _context()

    initial = controller.poll(context=context, now_monotonic_ns=1_000_000_000)
    controller.mark_capture_started(context=context, now_monotonic_ns=1_000_000_000)
    early = controller.poll(context=context, now_monotonic_ns=5_000_000_000)
    due = controller.poll(context=context, now_monotonic_ns=11_000_000_000)

    assert initial.kind is adaptive.CaptureTriggerKind.CADENCE
    assert early.kind is adaptive.CaptureTriggerKind.NONE
    assert due.kind is adaptive.CaptureTriggerKind.CADENCE
    assert controller.pending_change_count <= 1


def test_window_change_is_debounced_and_latest_change_replaces_pending_trigger() -> None:
    controller = adaptive.AdaptiveCaptureController(
        cadence_seconds=30.0,
        change_threshold=0.05,
        debounce_seconds=0.25,
    )
    first = _context(window_id="41")
    second = _context(window_id="42")
    third = _context(window_id="43")

    controller.mark_capture_started(context=first, now_monotonic_ns=1_000_000_000)
    first_change = controller.poll(context=second, now_monotonic_ns=1_100_000_000)
    replaced = controller.poll(context=third, now_monotonic_ns=1_200_000_000)
    stable = controller.poll(context=third, now_monotonic_ns=1_460_000_000)

    assert first_change.kind is adaptive.CaptureTriggerKind.NONE
    assert replaced.kind is adaptive.CaptureTriggerKind.NONE
    assert stable.kind is adaptive.CaptureTriggerKind.CONTEXT_CHANGE
    assert controller.pending_change_count == 0


def test_near_duplicate_extends_span_only_inside_same_privacy_context() -> None:
    controller = adaptive.AdaptiveCaptureController(
        cadence_seconds=10.0,
        change_threshold=0.05,
        debounce_seconds=0.25,
    )
    context = _context()
    fingerprint = adaptive.perceptual_dhash_rgb8(_gradient_rgb(), width=18, height=16)
    nearby = adaptive.perceptual_dhash_rgb8(
        _gradient_rgb(changed_pixel=True), width=18, height=16
    )

    first = controller.classify_frame(
        context=context,
        fingerprint=fingerprint,
        observed_at_monotonic_ns=1_000_000_000,
    )
    duplicate = controller.classify_frame(
        context=context,
        fingerprint=nearby,
        observed_at_monotonic_ns=2_000_000_000,
    )
    policy_changed = controller.classify_frame(
        context=_context(policy_revision="policy-b"),
        fingerprint=nearby,
        observed_at_monotonic_ns=3_000_000_000,
    )

    assert first.disposition is adaptive.FrameDisposition.ACCEPT
    assert first.span_count == 1
    assert duplicate.disposition is adaptive.FrameDisposition.COALESCE
    assert duplicate.span_count == 2
    assert policy_changed.disposition is adaptive.FrameDisposition.ACCEPT
    assert policy_changed.span_count == 1


def test_generation_and_configuration_changes_reset_dedup_state() -> None:
    controller = adaptive.AdaptiveCaptureController(
        cadence_seconds=10.0,
        change_threshold=0.05,
        debounce_seconds=0.25,
    )
    fingerprint = adaptive.perceptual_dhash_rgb8(_gradient_rgb(), width=18, height=16)

    controller.classify_frame(
        context=_context(),
        fingerprint=fingerprint,
        observed_at_monotonic_ns=1_000_000_000,
    )
    new_generation = controller.classify_frame(
        context=_context(generation=8),
        fingerprint=fingerprint,
        observed_at_monotonic_ns=2_000_000_000,
    )
    new_configuration = controller.classify_frame(
        context=_context(generation=8, configuration_revision="config-b"),
        fingerprint=fingerprint,
        observed_at_monotonic_ns=3_000_000_000,
    )

    assert new_generation.disposition is adaptive.FrameDisposition.ACCEPT
    assert new_configuration.disposition is adaptive.FrameDisposition.ACCEPT


def test_overload_backs_off_cadence_without_buffering_events() -> None:
    controller = adaptive.AdaptiveCaptureController(
        cadence_seconds=10.0,
        change_threshold=0.05,
        debounce_seconds=0.25,
        max_backoff_multiplier=4,
    )
    context = _context()
    controller.mark_capture_started(context=context, now_monotonic_ns=1_000_000_000)

    controller.note_overload()
    controller.note_overload()
    suppressed = controller.poll(context=context, now_monotonic_ns=15_000_000_000)
    eventually_due = controller.poll(context=context, now_monotonic_ns=41_000_000_000)
    controller.note_success()

    assert suppressed.kind is adaptive.CaptureTriggerKind.NONE
    assert eventually_due.kind is adaptive.CaptureTriggerKind.CADENCE
    assert suppressed.effective_cadence_seconds == 40.0
    assert controller.pending_change_count <= 1
    assert controller.effective_cadence_seconds == 20.0


def test_controller_state_repr_contains_no_content_values() -> None:
    controller = adaptive.AdaptiveCaptureController(
        cadence_seconds=10.0,
        change_threshold=0.05,
        debounce_seconds=0.25,
    )
    sensitive = _context(application="app-secret", workspace="workspace-secret")
    controller.mark_capture_started(context=sensitive, now_monotonic_ns=1_000_000_000)

    rendered = repr(controller)
    assert "app-secret" not in rendered
    assert "workspace-secret" not in rendered
