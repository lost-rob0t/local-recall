from __future__ import annotations

import pytest

from local_recall.domain.lifecycle import CaptureState, TransitionReason
from local_recall.lifecycle import (
    PauseCapture,
    ResumeCapture,
    SetAutomaticCaptureBlock,
    StaleCaptureGeneration,
    StartCapture,
)

from .support import MutableConfigurationSource, ask_result, start_actor, wait_for_state


def test_lock_invalidates_generation_and_unlock_does_not_revive_old_work() -> None:
    actor_ref, gate, _source, coordinator, _audit = start_actor(enabled=True)
    try:
        before = wait_for_state(actor_ref, CaptureState.RECORDING)
        assert before.generation is not None

        locked = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.SESSION_LOCKED),
        )
        assert locked.snapshot.state is CaptureState.PAUSED
        assert locked.snapshot.generation is not None
        assert locked.snapshot.generation.value > before.generation.value
        with pytest.raises(StaleCaptureGeneration):
            gate.require_current_generation(before.generation)

        unlocked = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=False, reason=TransitionReason.SESSION_UNLOCKED),
        )
        assert unlocked.snapshot.state is CaptureState.RECORDING
        assert unlocked.snapshot.generation == locked.snapshot.generation
        with pytest.raises(StaleCaptureGeneration):
            gate.require_current_generation(before.generation)
        assert ("cancel_queued", before.generation.value) in coordinator.calls
        assert ("cancel_in_flight", before.generation.value) in coordinator.calls
    finally:
        actor_ref.stop(block=True, timeout=2)


def test_duplicate_lock_event_does_not_increment_generation_twice() -> None:
    actor_ref, _gate, _source, _coordinator, _audit = start_actor(enabled=True)
    try:
        first = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.SESSION_LOCKED),
        )
        second = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.SESSION_LOCKED),
        )

        assert first.snapshot.generation == second.snapshot.generation
        assert second.changed is False
    finally:
        actor_ref.stop(block=True, timeout=2)


def test_manual_pause_is_not_overridden_by_unlock() -> None:
    actor_ref, _gate, _source, _coordinator, _audit = start_actor(enabled=True)
    try:
        paused = ask_result(actor_ref, PauseCapture())
        assert paused.snapshot.state is CaptureState.PAUSED
        ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.SESSION_LOCKED),
        )
        unlocked = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=False, reason=TransitionReason.SESSION_UNLOCKED),
        )

        assert unlocked.snapshot.state is CaptureState.PAUSED
        resumed = ask_result(actor_ref, ResumeCapture())
        assert resumed.snapshot.state is CaptureState.RECORDING
    finally:
        actor_ref.stop(block=True, timeout=2)


def test_user_resume_is_rejected_while_automatic_block_is_active() -> None:
    actor_ref, _gate, _source, _coordinator, _audit = start_actor(enabled=True)
    try:
        ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.IDLE),
        )

        result = ask_result(actor_ref, ResumeCapture())

        assert result.accepted is False
        assert result.reason_code == "session_safety_blocked"
        assert result.snapshot.state is CaptureState.PAUSED
    finally:
        actor_ref.stop(block=True, timeout=2)


def test_block_while_off_is_preserved_across_next_start() -> None:
    source = MutableConfigurationSource(False)
    actor_ref, _gate, _source, _coordinator, _audit = start_actor(enabled=False, source=source)
    try:
        result = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.SESSION_LOCKED),
        )
        assert result.snapshot.state is CaptureState.OFF
        source.set_enabled(True)
        ask_result(actor_ref, StartCapture())
        current = wait_for_state(actor_ref, CaptureState.PAUSED)
        assert current.generation is not None
    finally:
        actor_ref.stop(block=True, timeout=2)


def test_rapid_lock_unlock_lock_has_monotonic_generations() -> None:
    actor_ref, _gate, _source, _coordinator, _audit = start_actor(enabled=True)
    try:
        first = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.SESSION_LOCKED),
        )
        ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=False, reason=TransitionReason.SESSION_UNLOCKED),
        )
        second = ask_result(
            actor_ref,
            SetAutomaticCaptureBlock(blocked=True, reason=TransitionReason.SESSION_LOCKED),
        )

        assert first.snapshot.generation is not None
        assert second.snapshot.generation is not None
        assert second.snapshot.generation.value == first.snapshot.generation.value + 1
    finally:
        actor_ref.stop(block=True, timeout=2)
