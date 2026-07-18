from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pykka
import pytest

from local_recall.domain.lifecycle import CaptureState, TransitionReason
from local_recall.lifecycle import (
    CaptureGate,
    CaptureGateClosed,
    CaptureGateOwnershipError,
    FaultCapture,
    LifecycleActor,
    LifecycleFaultCode,
    PauseCapture,
    ResumeCapture,
    StaleCaptureGeneration,
    StartCapture,
    StopCapture,
)

from .support import (
    BlockingCoordinator,
    BlockingPreflight,
    CancellationAwarePreflight,
    MutableConfigurationSource,
    SyntheticAuditSink,
    SyntheticWorkCoordinator,
    UncooperativePreflight,
    ask_result,
    ask_snapshot,
    snapshot,
    start_actor,
    wait_for_state,
)


def test_starting_state_rejects_capture_and_persistence() -> None:
    source = MutableConfigurationSource(False)
    gate = CaptureGate()
    preflight = BlockingPreflight()
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=source,
        preflight=preflight,
        work_coordinator=SyntheticWorkCoordinator(),
        audit_sink=SyntheticAuditSink(),
        stop_timeout_seconds=1,
    )
    ask_snapshot(actor_ref)
    source.set_enabled(True)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(ask_result, actor_ref, StartCapture())
        assert preflight.entered.wait(1)
        state = gate.snapshot()
        assert state.state is CaptureState.STARTING
        assert state.generation is not None
        with pytest.raises(CaptureGateClosed):
            gate.run_capture(lambda permit: permit)
        with pytest.raises(CaptureGateClosed):
            gate.run_persistence(state.generation, lambda permit: permit)
        assert future.result(timeout=1).snapshot.state is CaptureState.STARTING
        preflight.release.set()
        assert wait_for_state(actor_ref, CaptureState.RECORDING).state is CaptureState.RECORDING


def test_stopping_state_rejects_stale_persistence() -> None:
    coordinator = BlockingCoordinator()
    actor_ref, gate, _, _, _ = start_actor(
        enabled=True,
        coordinator=coordinator,
    )
    generation = snapshot(actor_ref).generation
    assert generation is not None

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(ask_result, actor_ref, StopCapture())
        assert coordinator.wait_entered.wait(1)
        assert gate.snapshot().state is CaptureState.STOPPING
        with pytest.raises((CaptureGateClosed, StaleCaptureGeneration)):
            gate.run_persistence(generation, lambda permit: permit)
        coordinator.wait_release.set()
        assert future.result(timeout=1).snapshot.state is CaptureState.OFF


def test_cancellation_failure_faults_but_still_clears_buffers() -> None:
    coordinator = SyntheticWorkCoordinator()
    coordinator.raise_cancel = True
    actor_ref, gate, _, _, _ = start_actor(enabled=True, coordinator=coordinator)

    result = ask_result(actor_ref, StopCapture())

    assert result.snapshot.state is CaptureState.FAULTED
    assert result.fault_code is LifecycleFaultCode.CANCELLATION_FAILURE
    assert any(name == "clear_volatile_buffers" for name, _ in coordinator.calls)
    with pytest.raises(CaptureGateClosed):
        gate.run_capture(lambda permit: permit)


def test_buffer_clear_failure_transitions_to_faulted() -> None:
    coordinator = SyntheticWorkCoordinator()
    coordinator.raise_clear = True
    actor_ref, _, _, _, _ = start_actor(enabled=True, coordinator=coordinator)

    result = ask_result(actor_ref, StopCapture())

    assert result.snapshot.state is CaptureState.FAULTED
    assert result.fault_code is LifecycleFaultCode.BUFFER_CLEAR_FAILURE


def test_audit_failure_faults_closed_and_cancels_active_generation() -> None:
    audit = SyntheticAuditSink()
    audit.fail_after = 1
    coordinator = SyntheticWorkCoordinator()
    actor_ref, gate, _, _, _ = start_actor(
        enabled=True,
        audit=audit,
        coordinator=coordinator,
    )

    state = snapshot(actor_ref)

    assert state.state is CaptureState.FAULTED
    assert any(name == "cancel_queued" for name, _ in coordinator.calls)
    with pytest.raises(CaptureGateClosed):
        gate.run_capture(lambda permit: permit)


def test_lifecycle_actor_uses_pykka_threading_actor() -> None:
    assert issubclass(LifecycleActor, pykka.ThreadingActor)


def test_non_owner_thread_cannot_mutate_gate_state() -> None:
    gate = CaptureGate()

    with pytest.raises(CaptureGateOwnershipError):
        gate.begin_start(TransitionReason.USER_START, "config-v1")


def test_stop_signals_preflight_cancellation_token() -> None:
    source = MutableConfigurationSource(False)
    gate = CaptureGate()
    preflight = CancellationAwarePreflight()
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=source,
        preflight=preflight,
        work_coordinator=SyntheticWorkCoordinator(),
        audit_sink=SyntheticAuditSink(),
        preflight_timeout_seconds=1,
        stop_timeout_seconds=1,
    )
    ask_snapshot(actor_ref)
    source.set_enabled(True)

    started = ask_result(actor_ref, StartCapture())
    assert started.snapshot.state is CaptureState.STARTING
    assert preflight.entered.wait(1)

    stopped = ask_result(actor_ref, StopCapture())

    assert stopped.snapshot.state is CaptureState.OFF
    assert preflight.cancelled.is_set()


def test_uncooperative_preflight_times_out_to_faulted_without_reopening_gate() -> None:
    source = MutableConfigurationSource(False)
    gate = CaptureGate()
    preflight = UncooperativePreflight()
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=source,
        preflight=preflight,
        work_coordinator=SyntheticWorkCoordinator(),
        audit_sink=SyntheticAuditSink(),
        preflight_timeout_seconds=1,
        stop_timeout_seconds=0.05,
    )
    ask_snapshot(actor_ref)
    source.set_enabled(True)

    started = ask_result(actor_ref, StartCapture())
    assert started.snapshot.state is CaptureState.STARTING
    assert preflight.entered.wait(1)
    try:
        stopped = ask_result(actor_ref, StopCapture())
        assert stopped.snapshot.state is CaptureState.FAULTED
        assert stopped.fault_code is LifecycleFaultCode.QUIESCENCE_TIMEOUT
        with pytest.raises(CaptureGateClosed):
            gate.run_capture(lambda permit: permit)
    finally:
        preflight.release.set()

    wait_for_state(actor_ref, CaptureState.FAULTED)


def test_both_cancellation_paths_are_attempted_when_first_fails() -> None:
    coordinator = SyntheticWorkCoordinator()
    coordinator.raise_cancel = True
    coordinator.raise_in_flight = True
    actor_ref, _, _, _, _ = start_actor(enabled=True, coordinator=coordinator)

    result = ask_result(actor_ref, StopCapture())

    assert result.snapshot.state is CaptureState.FAULTED
    assert result.fault_code is LifecycleFaultCode.CANCELLATION_FAILURE
    assert coordinator.calls[:2] == [
        ("cancel_queued", 1),
        ("cancel_in_flight", 1),
    ]


def test_explicit_fault_command_is_idempotent_and_closes_gate() -> None:
    actor_ref, gate, _, _, _ = start_actor(enabled=True)

    first = ask_result(
        actor_ref,
        FaultCapture(fault_code=LifecycleFaultCode.POLICY_FAILURE),
    )
    second = ask_result(
        actor_ref,
        FaultCapture(fault_code=LifecycleFaultCode.POLICY_FAILURE),
    )

    assert first.snapshot.state is CaptureState.FAULTED
    assert first.changed
    assert second.snapshot.state is CaptureState.FAULTED
    assert second.accepted
    assert not second.changed
    with pytest.raises(CaptureGateClosed):
        gate.run_capture(lambda permit: permit)


def test_stop_from_faulted_clears_buffers_and_returns_off() -> None:
    actor_ref, _, _, coordinator, _ = start_actor(enabled=True)
    ask_result(actor_ref, FaultCapture(fault_code=LifecycleFaultCode.POLICY_FAILURE))

    stopped = ask_result(actor_ref, StopCapture())

    assert stopped.snapshot.state is CaptureState.OFF
    assert coordinator.calls[-1] == ("clear_volatile_buffers", None)


def test_transition_sequence_is_deterministic() -> None:
    actor_ref, _, _, _, audit = start_actor(enabled=True)
    ask_result(actor_ref, PauseCapture())
    ask_result(actor_ref, ResumeCapture())
    ask_result(actor_ref, StopCapture())

    assert [event.current for event in audit.events] == [
        CaptureState.STARTING,
        CaptureState.RECORDING,
        CaptureState.PAUSED,
        CaptureState.RECORDING,
        CaptureState.STOPPING,
        CaptureState.OFF,
    ]


def test_stop_during_preflight_invalidates_before_preflight_returns() -> None:
    source = MutableConfigurationSource(False)
    gate = CaptureGate()
    preflight = BlockingPreflight()
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=source,
        preflight=preflight,
        work_coordinator=SyntheticWorkCoordinator(),
        audit_sink=SyntheticAuditSink(),
        preflight_timeout_seconds=1,
        stop_timeout_seconds=1,
    )
    ask_snapshot(actor_ref)
    source.set_enabled(True)

    started = ask_result(actor_ref, StartCapture())
    assert started.snapshot.state is CaptureState.STARTING
    assert preflight.entered.wait(1)
    generation = gate.snapshot().generation
    assert generation is not None

    with ThreadPoolExecutor(max_workers=1) as executor:
        stop_future = executor.submit(ask_result, actor_ref, StopCapture())
        deadline = time.monotonic() + 0.25
        while gate.snapshot().state is not CaptureState.STOPPING and time.monotonic() < deadline:
            threading.Event().wait(0.005)
        assert gate.snapshot().state is CaptureState.STOPPING
        with pytest.raises(CaptureGateClosed):
            gate.run_capture(lambda permit: permit)
        with pytest.raises((CaptureGateClosed, StaleCaptureGeneration)):
            gate.run_persistence(generation, lambda permit: permit)
        preflight.release.set()
        stopped = stop_future.result(timeout=1)

    assert stopped.snapshot.state is CaptureState.OFF
    assert gate.snapshot().state is CaptureState.OFF
