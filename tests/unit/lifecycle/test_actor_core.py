from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from local_recall.domain.lifecycle import CaptureGeneration, CaptureState
from local_recall.lifecycle import (
    CaptureGate,
    CaptureGateClosed,
    CaptureWorkPermit,
    LifecycleCommandResult,
    LifecycleFaultCode,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
    PauseCapture,
    ResumeCapture,
    StaleCaptureGeneration,
    StartCapture,
    StopCapture,
)

from .support import (
    MutableConfigurationSource,
    SyntheticPreflight,
    SyntheticWorkCoordinator,
    ask_result,
    snapshot,
    start_actor,
)


def test_process_startup_defaults_to_off() -> None:
    actor_ref, gate, _, _, audit = start_actor(enabled=False)

    assert snapshot(actor_ref).state is CaptureState.OFF
    assert gate.snapshot().generation is None
    assert audit.events == []


def test_explicit_startup_opt_in_runs_preflight_and_records() -> None:
    requests: list[LifecyclePreflightRequest] = []
    actor_ref, gate, _, _, audit = start_actor(
        enabled=True,
        preflight=SyntheticPreflight(requests=requests),
    )

    state = snapshot(actor_ref)
    assert state.state is CaptureState.RECORDING
    assert state.generation == CaptureGeneration(1)
    assert len(requests) == 1
    assert [event.current for event in audit.events] == [
        CaptureState.STARTING,
        CaptureState.RECORDING,
    ]
    assert gate.generation_epoch == 1


@pytest.mark.parametrize(
    "fault_code",
    [
        LifecycleFaultCode.UNSUPPORTED_SESSION,
        LifecycleFaultCode.ENCRYPTION_UNAVAILABLE,
        LifecycleFaultCode.POLICY_FAILURE,
    ],
)
def test_preflight_failure_never_reaches_recording(
    fault_code: LifecycleFaultCode,
) -> None:
    actor_ref, gate, _, _, audit = start_actor(
        enabled=True,
        preflight=SyntheticPreflight(result=LifecyclePreflightResult.failure(fault_code)),
    )

    state = snapshot(actor_ref)
    assert state.state is CaptureState.FAULTED
    assert state.generation is None
    assert not state.critical_dependencies_healthy
    assert all(event.current is not CaptureState.RECORDING for event in audit.events)
    assert audit.events[-1].fault_code is fault_code
    with pytest.raises(CaptureGateClosed):
        gate.run_capture(lambda permit: permit)


def test_pause_blocks_new_capture_but_allows_current_generation_persistence() -> None:
    actor_ref, gate, _, _, _ = start_actor(enabled=True)
    generation = snapshot(actor_ref).generation
    assert generation is not None

    paused = ask_result(actor_ref, PauseCapture())
    assert paused.snapshot.state is CaptureState.PAUSED
    with pytest.raises(CaptureGateClosed):
        gate.run_capture(lambda permit: permit)
    assert gate.run_persistence(generation, lambda permit: permit.generation) == generation

    resumed = ask_result(actor_ref, ResumeCapture())
    assert resumed.snapshot.state is CaptureState.RECORDING
    assert resumed.snapshot.generation == generation


def test_concurrent_start_commands_are_serialized_and_idempotent() -> None:
    source = MutableConfigurationSource(False)
    actor_ref, _, _, _, audit = start_actor(source=source)
    source.set_enabled(True)

    with ThreadPoolExecutor(max_workers=8) as executor:

        def send_start(_: int) -> LifecycleCommandResult:
            return ask_result(actor_ref, StartCapture())

        results = list(executor.map(send_start, range(8)))

    assert snapshot(actor_ref).state is CaptureState.RECORDING
    assert sum(result.changed for result in results) == 1
    assert all(result.accepted for result in results)
    assert [event.current for event in audit.events] == [
        CaptureState.STARTING,
        CaptureState.RECORDING,
    ]


def test_stop_invalidates_generation_before_pipeline_cancellation() -> None:
    gate = CaptureGate()
    coordinator = SyntheticWorkCoordinator()
    actor_ref, _, _, _, _ = start_actor(
        enabled=True,
        gate=gate,
        coordinator=coordinator,
    )
    generation = snapshot(actor_ref).generation
    assert generation is not None
    persistence_called = False

    def assert_stale(captured_generation: CaptureGeneration) -> None:
        nonlocal persistence_called
        assert captured_generation == generation
        with pytest.raises((CaptureGateClosed, StaleCaptureGeneration)):
            gate.run_persistence(
                generation,
                lambda permit: _mark_persistence_called(permit),
            )

    def _mark_persistence_called(permit: object) -> object:
        nonlocal persistence_called
        persistence_called = True
        return permit

    coordinator.on_cancel = assert_stale
    result = ask_result(actor_ref, StopCapture())

    assert result.snapshot.state is CaptureState.OFF
    assert not persistence_called
    assert coordinator.calls == [
        ("cancel_queued", generation.value),
        ("cancel_in_flight", generation.value),
        ("wait_for_quiescence", generation.value),
        ("clear_volatile_buffers", generation.value),
    ]
    assert gate.generation_epoch > generation.value


def test_stop_cooperatively_cancels_and_waits_for_in_flight_capture() -> None:
    actor_ref, gate, _, _, _ = start_actor(enabled=True)
    started = threading.Event()
    finished = threading.Event()

    def capture_operation() -> None:
        def run(permit: CaptureWorkPermit) -> None:
            started.set()
            assert permit.wait_cancelled(1)
            finished.set()

        gate.run_capture(run)

    thread = threading.Thread(target=capture_operation)
    thread.start()
    assert started.wait(1)

    result = ask_result(actor_ref, StopCapture())
    thread.join(1)

    assert result.snapshot.state is CaptureState.OFF
    assert finished.is_set()
    assert not thread.is_alive()


def test_quiescence_failure_transitions_to_faulted() -> None:
    coordinator = SyntheticWorkCoordinator()
    coordinator.quiescent = False
    actor_ref, gate, _, _, audit = start_actor(
        enabled=True,
        coordinator=coordinator,
    )

    result = ask_result(actor_ref, StopCapture())

    assert result.snapshot.state is CaptureState.FAULTED
    assert result.fault_code is LifecycleFaultCode.QUIESCENCE_TIMEOUT
    assert audit.events[-1].fault_code is LifecycleFaultCode.QUIESCENCE_TIMEOUT
    with pytest.raises(CaptureGateClosed):
        gate.run_capture(lambda permit: permit)


def test_repeated_stop_is_idempotent() -> None:
    actor_ref, _, _, coordinator, _ = start_actor(enabled=True)

    first = ask_result(actor_ref, StopCapture())
    second = ask_result(actor_ref, StopCapture())

    assert first.changed
    assert second.accepted
    assert not second.changed
    assert second.snapshot.state is CaptureState.OFF
    assert [name for name, _ in coordinator.calls].count("clear_volatile_buffers") == 1


def test_actor_stop_does_not_leave_gate_recording() -> None:
    actor_ref, gate, _, _, _ = start_actor(enabled=True)
    assert gate.snapshot().state is CaptureState.RECORDING

    assert actor_ref.stop(block=True, timeout=2)

    assert gate.snapshot().state is CaptureState.OFF
    with pytest.raises(CaptureGateClosed):
        gate.run_capture(lambda permit: permit)


def test_restart_does_not_reuse_previous_runtime_state() -> None:
    first_ref, first_gate, _, _, _ = start_actor(enabled=True)
    assert first_gate.snapshot().state is CaptureState.RECORDING
    first_ref.stop(block=True, timeout=2)

    second_ref, second_gate, _, _, _ = start_actor(enabled=False)
    assert snapshot(second_ref).state is CaptureState.OFF
    assert second_gate.generation_epoch == 0


def test_unknown_tell_faults_closed_without_auditing_message_content() -> None:
    actor_ref, gate, _, _, audit = start_actor(enabled=True)
    marker = "SENSITIVE-MESSAGE-CONTENT"

    actor_ref.tell({"unknown": marker})
    for _ in range(100):
        if gate.snapshot().state is CaptureState.FAULTED:
            break
        threading.Event().wait(0.01)

    assert gate.snapshot().state is CaptureState.FAULTED
    assert marker not in repr(audit.events)
    assert audit.events[-1].fault_code is LifecycleFaultCode.ACTOR_FAILURE


def test_audit_events_contain_only_sanitized_transition_fields() -> None:
    actor_ref, _, _, _, audit = start_actor(enabled=True)
    ask_result(actor_ref, StopCapture())

    assert audit.events
    for event in audit.events:
        assert event.event_type == "capture.lifecycle.transition"
        assert event.configuration_revision in {"config-on", None}
        assert not hasattr(event, "exception")
        assert not hasattr(event, "message")
        assert not hasattr(event, "payload")
