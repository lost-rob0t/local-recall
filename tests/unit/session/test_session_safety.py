from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from local_recall.config import IdleResumeBehavior, IdleSettings
from local_recall.domain.lifecycle import (
    CaptureGeneration,
    CaptureState,
    CaptureStateSnapshot,
    TransitionReason,
)
from local_recall.domain.policy import PolicyStatus
from local_recall.lifecycle import LifecycleCommandResult
from local_recall.session.safety import (
    IdleObservation,
    IdleState,
    LockObservation,
    LockState,
    SessionSafetyController,
    SessionSafetyFailureCode,
    SessionSafetyState,
)

NOW = datetime(2026, 8, 12, 18, 30, tzinfo=UTC)


class FakeClock:
    def __init__(self) -> None:
        self.current = NOW
        self.monotonic = 1_000_000_000

    def now(self) -> datetime:
        return self.current

    def monotonic_ns(self) -> int:
        return self.monotonic

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)
        self.monotonic += int(seconds * 1_000_000_000)


class FakePolicy:
    def __init__(self) -> None:
        self.locked = False
        self.privacy = False
        self.generation = 1

    def set_session_locked(self, locked: bool) -> None:
        if self.locked != locked:
            self.generation += 1
        self.locked = locked

    def status(self) -> PolicyStatus:
        return PolicyStatus(
            policy_revision="synthetic-v1",
            policy_generation=self.generation,
            enabled_rule_count=0,
            privacy_mode=self.privacy,
            session_locked=self.locked,
            healthy=True,
        )


@dataclass
class FakeLifecycle:
    generation: int = 1
    calls: list[tuple[bool, TransitionReason]] = field(
        default_factory=lambda: list[tuple[bool, TransitionReason]](), init=False
    )

    def apply(self, *, blocked: bool, reason: TransitionReason) -> LifecycleCommandResult:
        self.calls.append((blocked, reason))
        if blocked:
            self.generation += 1
        return LifecycleCommandResult(
            accepted=True,
            changed=True,
            snapshot=CaptureStateSnapshot(
                state=CaptureState.PAUSED if blocked else CaptureState.RECORDING,
                generation=CaptureGeneration(self.generation),
                observed_at=NOW,
                privacy_mode=False,
                critical_dependencies_healthy=True,
            ),
            reason_code="synthetic",
        )


def lock(state: LockState, *, observed_at: datetime = NOW) -> LockObservation:
    return LockObservation(
        state=state,
        observed_at=observed_at,
        source_id="logind",
        source_revision="login1-v1",
    )


def idle(
    state: IdleState,
    *,
    seconds: float | None = None,
    source: str = "xorg-idle",
    observed_at: datetime = NOW,
) -> IdleObservation:
    return IdleObservation(
        state=state,
        observed_at=observed_at,
        source_id=source,
        source_revision="synthetic-v1",
        idle_seconds=seconds,
    )


def controller(
    *,
    settings: IdleSettings | None = None,
) -> tuple[SessionSafetyController, FakePolicy, FakeLifecycle, FakeClock]:
    policy = FakePolicy()
    lifecycle = FakeLifecycle()
    clock = FakeClock()
    value = SessionSafetyController(
        policy=policy,
        lifecycle=lifecycle,
        idle_settings=settings,
        clock=clock,
    )
    return value, policy, lifecycle, clock


def test_unknown_lock_fails_closed_even_when_idle_source_reports_active() -> None:
    state = SessionSafetyState(
        lock=lock(LockState.UNKNOWN),
        idle=idle(IdleState.ACTIVE, source="activitywatch"),
    )

    assert state.capture_blocked is True
    assert state.effective_reason == "lock-unknown"


def test_controller_starts_fail_closed_until_lock_state_is_known() -> None:
    value, policy, lifecycle, _clock = controller()

    assert policy.locked is True
    assert value.capture_blocked is True
    assert lifecycle.calls == []


def test_locked_state_dominates_active_idle_and_duplicate_lock_is_idempotent() -> None:
    value, policy, lifecycle, _clock = controller()
    value.apply_lock(lock(LockState.UNLOCKED))
    value.apply_idle((idle(IdleState.ACTIVE, seconds=0.0),))
    lifecycle.calls.clear()

    value.apply_lock(lock(LockState.LOCKED))
    value.apply_idle((idle(IdleState.ACTIVE, seconds=0.0),))
    value.apply_lock(lock(LockState.LOCKED))

    assert policy.locked is True
    assert value.capture_blocked is True
    assert lifecycle.calls == [(True, TransitionReason.SESSION_LOCKED)]


def test_stale_unlocked_observation_fails_closed() -> None:
    value, policy, lifecycle, clock = controller()
    value.apply_lock(lock(LockState.UNLOCKED))
    lifecycle.calls.clear()
    clock.advance(6.0)

    value.refresh()

    assert policy.locked is True
    assert value.status().lock_state is LockState.UNKNOWN
    assert value.status().last_failure_code is SessionSafetyFailureCode.STALE
    assert lifecycle.calls == [(True, TransitionReason.SESSION_LOCKED)]


def test_idle_threshold_is_exact_and_uses_duration_when_available() -> None:
    settings = IdleSettings(enabled=True, threshold_seconds=180.0)
    value, _policy, lifecycle, _clock = controller(settings=settings)
    value.apply_lock(lock(LockState.UNLOCKED))
    lifecycle.calls.clear()

    value.apply_idle((idle(IdleState.IDLE, seconds=179.999),))
    assert value.status().idle_state is IdleState.ACTIVE
    assert lifecycle.calls == []

    value.apply_idle((idle(IdleState.IDLE, seconds=180.0),))
    assert value.status().idle_state is IdleState.IDLE
    assert lifecycle.calls == [(True, TransitionReason.IDLE)]


def test_conflicting_idle_sources_choose_idle_conservatively() -> None:
    settings = IdleSettings(enabled=True, threshold_seconds=60.0)
    value, _policy, lifecycle, _clock = controller(settings=settings)
    value.apply_lock(lock(LockState.UNLOCKED))
    lifecycle.calls.clear()

    value.apply_idle(
        (
            idle(IdleState.ACTIVE, source="activitywatch"),
            idle(IdleState.IDLE, seconds=70.0, source="xorg-idle"),
        )
    )

    assert value.status().idle_state is IdleState.IDLE
    assert value.status().last_failure_code is SessionSafetyFailureCode.SOURCE_CONFLICT
    assert lifecycle.calls == [(True, TransitionReason.IDLE)]


def test_missing_idle_support_does_not_disable_lock_blocking() -> None:
    settings = IdleSettings(enabled=True)
    value, policy, lifecycle, _clock = controller(settings=settings)
    value.apply_lock(lock(LockState.UNLOCKED))
    value.apply_idle(())
    lifecycle.calls.clear()

    value.apply_lock(lock(LockState.LOCKED))

    assert policy.locked is True
    assert value.capture_blocked is True
    assert lifecycle.calls == [(True, TransitionReason.SESSION_LOCKED)]


def test_active_grace_resumes_only_after_fixed_monotonic_interval() -> None:
    settings = IdleSettings(
        enabled=True,
        threshold_seconds=60.0,
        resume_behavior=IdleResumeBehavior.ACTIVE_GRACE,
        active_grace_seconds=5.0,
    )
    value, _policy, lifecycle, clock = controller(settings=settings)
    value.apply_lock(lock(LockState.UNLOCKED))
    lifecycle.calls.clear()
    value.apply_idle((idle(IdleState.IDLE, seconds=120.0),))
    value.apply_idle((idle(IdleState.ACTIVE, seconds=0.0),))

    clock.advance(4.999)
    value.refresh()
    assert lifecycle.calls == [(True, TransitionReason.IDLE)]

    clock.advance(0.001)
    value.refresh()
    assert lifecycle.calls == [
        (True, TransitionReason.IDLE),
        (False, TransitionReason.ACTIVE),
    ]


def test_manual_resume_mode_requires_explicit_acknowledgement() -> None:
    settings = IdleSettings(
        enabled=True,
        threshold_seconds=60.0,
        resume_behavior=IdleResumeBehavior.MANUAL,
    )
    value, _policy, lifecycle, _clock = controller(settings=settings)
    value.apply_lock(lock(LockState.UNLOCKED))
    lifecycle.calls.clear()
    value.apply_idle((idle(IdleState.IDLE, seconds=120.0),))
    value.apply_idle((idle(IdleState.ACTIVE, seconds=0.0),))

    assert lifecycle.calls == [(True, TransitionReason.IDLE)]
    value.acknowledge_idle_resume()
    assert lifecycle.calls == [
        (True, TransitionReason.IDLE),
        (False, TransitionReason.ACTIVE),
    ]


def test_privacy_mode_prevents_idle_auto_resume() -> None:
    settings = IdleSettings(enabled=True, threshold_seconds=60.0)
    value, policy, lifecycle, _clock = controller(settings=settings)
    value.apply_lock(lock(LockState.UNLOCKED))
    lifecycle.calls.clear()
    value.apply_idle((idle(IdleState.IDLE, seconds=120.0),))
    policy.privacy = True

    value.apply_idle((idle(IdleState.ACTIVE, seconds=0.0),))

    assert lifecycle.calls == [(True, TransitionReason.IDLE)]


def test_restrictive_reload_blocks_and_permissive_reload_cannot_revive_old_generation() -> None:
    value, _policy, lifecycle, _clock = controller(
        settings=IdleSettings(enabled=True, threshold_seconds=300.0)
    )
    value.apply_lock(lock(LockState.UNLOCKED))
    value.apply_idle((idle(IdleState.IDLE, seconds=200.0),))
    lifecycle.calls.clear()
    old_generation = lifecycle.generation

    value.replace_idle_settings(IdleSettings(enabled=True, threshold_seconds=100.0))
    blocked_generation = lifecycle.generation
    value.replace_idle_settings(IdleSettings(enabled=False))

    assert blocked_generation > old_generation
    assert lifecycle.generation == blocked_generation
    assert lifecycle.calls == [
        (True, TransitionReason.IDLE),
        (False, TransitionReason.ACTIVE),
    ]


def test_status_contains_only_sanitized_control_values() -> None:
    value, _policy, _lifecycle, _clock = controller()
    value.apply_lock(
        LockObservation(
            state=LockState.UNKNOWN,
            observed_at=NOW,
            source_id="logind",
            source_revision="login1-v1",
            failure_code=SessionSafetyFailureCode.DISCONNECTED,
        )
    )

    rendered = repr(value.status().as_dict())
    for secret in ("alice@example.test", "FAKE_TOKEN_123", "sensitive.example", "sudo secret"):
        assert secret not in rendered
