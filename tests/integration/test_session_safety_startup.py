from __future__ import annotations

import time
from datetime import UTC, datetime

import pykka
import pytest

from local_recall.config import LocalRecallConfig, PrivacyProfile, RuleEffect, RuleSettings
from local_recall.domain.lifecycle import CaptureState
from local_recall.lifecycle import CaptureGate, CaptureGateClosed, LifecycleActor
from local_recall.policy import PolicyEngine
from local_recall.session.safety import (
    LockObservation,
    LockState,
    SafetyObservationRequest,
    SessionSafetyFailureCode,
    SessionSafetyPreflight,
)
from tests.unit.lifecycle.support import (
    MutableConfigurationSource,
    SyntheticAuditSink,
    SyntheticPreflight,
    SyntheticWorkCoordinator,
    wait_for_state,
)

NOW = datetime(2026, 8, 12, 20, 30, tzinfo=UTC)


class SyntheticLockSource:
    source_id = "logind"

    def __init__(self, state: LockState, *, fail: bool = False) -> None:
        self.state = state
        self.fail = fail
        self.calls = 0

    async def observe(self, request: SafetyObservationRequest) -> LockObservation:
        assert request.deadline_monotonic_ns > time.monotonic_ns()
        self.calls += 1
        if self.fail:
            raise RuntimeError("FAKE_TOKEN_123 alice@example.test")
        return LockObservation(
            state=self.state,
            observed_at=NOW,
            source_id=self.source_id,
            source_revision="synthetic-v1",
            failure_code=(
                SessionSafetyFailureCode.UNAVAILABLE if self.state is LockState.UNKNOWN else None
            ),
        )


def policy() -> PolicyEngine:
    return PolicyEngine(
        LocalRecallConfig(
            profile=PrivacyProfile.LOCAL_FIRST,
            rules=RuleSettings(default_effect=RuleEffect.ALLOW),
        ),
        revision="startup-policy-v1",
    )


def start_with_lock(
    state: LockState,
    *,
    fail: bool = False,
) -> tuple[pykka.ActorRef[LifecycleActor], CaptureGate, PolicyEngine, SyntheticLockSource]:
    gate = CaptureGate()
    source = MutableConfigurationSource(True)
    work = SyntheticWorkCoordinator()
    audit = SyntheticAuditSink()
    engine = policy()
    lock_source = SyntheticLockSource(state, fail=fail)
    preflight = SessionSafetyPreflight(
        base=SyntheticPreflight(),
        policy=engine,
        lock_source=lock_source,
        now=lambda: NOW,
    )
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=source,
        preflight=preflight,
        work_coordinator=work,
        audit_sink=audit,
        preflight_timeout_seconds=1,
        stop_timeout_seconds=1,
    )
    return actor_ref, gate, engine, lock_source


def test_daemon_startup_while_locked_has_no_transient_capture_window() -> None:
    actor_ref, gate, engine, lock_source = start_with_lock(LockState.LOCKED)
    try:
        current = wait_for_state(actor_ref, CaptureState.PAUSED)

        assert current.generation is not None
        assert engine.status().session_locked is True
        assert lock_source.calls == 1
        with pytest.raises(CaptureGateClosed):
            gate.run_capture(lambda _permit: b"pixels")
    finally:
        actor_ref.stop(block=True, timeout=2)


def test_daemon_restart_while_still_locked_remains_non_capturing() -> None:
    first_ref, _first_gate, _first_engine, _source = start_with_lock(LockState.LOCKED)
    try:
        wait_for_state(first_ref, CaptureState.PAUSED)
    finally:
        first_ref.stop(block=True, timeout=2)

    second_ref, second_gate, second_engine, _source = start_with_lock(LockState.LOCKED)
    try:
        wait_for_state(second_ref, CaptureState.PAUSED)
        assert second_engine.status().session_locked is True
        with pytest.raises(CaptureGateClosed):
            second_gate.run_capture(lambda _permit: b"pixels")
    finally:
        second_ref.stop(block=True, timeout=2)


def test_startup_unknown_or_failed_lock_source_fails_closed() -> None:
    for state, fail in ((LockState.UNKNOWN, False), (LockState.UNLOCKED, True)):
        actor_ref, gate, engine, _source = start_with_lock(state, fail=fail)
        try:
            wait_for_state(actor_ref, CaptureState.PAUSED)
            assert engine.status().session_locked is True
            with pytest.raises(CaptureGateClosed):
                gate.run_capture(lambda _permit: b"pixels")
        finally:
            actor_ref.stop(block=True, timeout=2)


def test_startup_explicit_unlocked_can_record_after_safety_query() -> None:
    actor_ref, gate, engine, lock_source = start_with_lock(LockState.UNLOCKED)
    try:
        current = wait_for_state(actor_ref, CaptureState.RECORDING)
        assert current.generation is not None
        assert engine.status().session_locked is False
        assert lock_source.calls == 1
        assert gate.run_capture(lambda _permit: b"ok") == b"ok"
    finally:
        actor_ref.stop(block=True, timeout=2)
