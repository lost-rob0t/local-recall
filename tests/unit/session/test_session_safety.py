from __future__ import annotations

from datetime import UTC, datetime

from local_recall.session.safety import (
    IdleObservation,
    IdleState,
    LockObservation,
    LockState,
    SessionSafetyState,
)


def test_unknown_lock_fails_closed_even_when_idle_source_reports_active() -> None:
    observed_at = datetime(2026, 8, 12, 18, 30, tzinfo=UTC)
    state = SessionSafetyState(
        lock=LockObservation(
            state=LockState.UNKNOWN,
            observed_at=observed_at,
            source_id="logind",
            source_revision="login1-v1",
        ),
        idle=IdleObservation(
            state=IdleState.ACTIVE,
            observed_at=observed_at,
            source_id="activitywatch",
            source_revision="activitywatch-afk-v1",
            idle_seconds=0.0,
        ),
    )

    assert state.capture_blocked is True
    assert state.effective_reason == "lock-unknown"
