from __future__ import annotations

from pathlib import Path

import pytest

from local_recall.config import IdleResumeBehavior, IdleSettings
from local_recall.session.logind import LogindSignal, parse_busctl_signal
from local_recall.session.safety import IdleObservation, IdleState, LockObservation, LockState

ROOT = Path(__file__).resolve().parents[2]
SENSITIVE = (
    "fake-user@example.test",
    "Sensitive Banking Window",
    "FAKE_TOKEN_123456",
    "sudo --password fake-command",
    "secret.example.test",
)


def test_lock_and_idle_models_do_not_repr_source_payload_values() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 8, 12, 21, 0, tzinfo=UTC)
    lock = LockObservation(
        state=LockState.UNKNOWN,
        observed_at=now,
        source_id="logind",
        source_revision="login1-v1",
    )
    idle = IdleObservation(
        state=IdleState.UNKNOWN,
        observed_at=now,
        source_id="activitywatch",
        source_revision="activitywatch-v1",
    )

    rendered = f"{lock!r} {idle!r}"
    for secret in SENSITIVE:
        assert secret not in rendered


def test_unrelated_or_malformed_logind_signals_cannot_spoof_unlock() -> None:
    unrelated = LogindSignal(
        object_path="/org/freedesktop/login1/session/_99",
        interface="org.freedesktop.login1.Session",
        member="Unlock",
    )
    assert unrelated.object_path.endswith("_99")
    assert parse_busctl_signal(("Path=garbage Interface=garbage Member=Unlock",)) is None
    assert (
        parse_busctl_signal(
            (
                "Type=signal",
                "Path=/org/freedesktop/login1/session/_32 "
                "Interface=org.freedesktop.login1.Session Member=TotallyNotUnlock",
            )
        )
        is None
    )


def test_idle_configuration_rejects_unbounded_or_ambiguous_values() -> None:
    with pytest.raises(ValueError):
        IdleSettings(threshold_seconds=0)
    with pytest.raises(ValueError):
        IdleSettings(threshold_seconds=86_401)
    with pytest.raises(ValueError):
        IdleSettings(
            resume_behavior=IdleResumeBehavior.ACTIVE_GRACE,
            active_grace_seconds=0,
        )
    with pytest.raises(ValueError):
        IdleSettings(
            resume_behavior=IdleResumeBehavior.IMMEDIATE,
            active_grace_seconds=5,
        )


def test_session_safety_modules_do_not_cross_capture_storage_or_provider_boundaries() -> None:
    paths = (
        ROOT / "src/local_recall/session/safety.py",
        ROOT / "src/local_recall/session/logind.py",
        ROOT / "src/local_recall/session/idle.py",
    )
    forbidden = (
        "local_recall.storage",
        "local_recall.providers",
        "capture_backend",
        ".persist(",
        "screenshot(",
    )

    for path in paths:
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{path.name} crosses security boundary via {token}"
