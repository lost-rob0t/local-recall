from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.session.logind import (
    BusctlResult,
    LogindLockStateSource,
    LogindSignal,
    parse_busctl_signal,
)
from local_recall.session.safety import (
    LockState,
    SafetyObservationRequest,
    SessionSafetyFailureCode,
)

NOW = datetime(2026, 8, 12, 19, 0, tzinfo=UTC)


@dataclass
class FakeRunner:
    results: list[BusctlResult]
    available: bool = True
    calls: list[tuple[str, ...]] = field(
        default_factory=lambda: list[tuple[str, ...]](), init=False
    )

    async def run(
        self,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> BusctlResult:
        assert timeout_seconds > 0
        assert max_output_bytes <= 4096
        self.calls.append(args)
        return self.results.pop(0)


def request() -> SafetyObservationRequest:
    return SafetyObservationRequest(
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=time.monotonic_ns() + 2_000_000_000,
    )


def source(*results: BusctlResult) -> tuple[LogindLockStateSource, FakeRunner]:
    runner = FakeRunner(list(results))
    value = LogindLockStateSource("c2", runner=runner, now=lambda: NOW)
    return value, runner


def test_startup_locked_queries_target_session_before_reporting_state() -> None:
    value, runner = source(
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b true\n"),
    )

    observation = asyncio.run(value.observe(request()))

    assert observation.state is LockState.LOCKED
    assert value.session_path == "/org/freedesktop/login1/session/_32"
    assert runner.calls[0][-2:] == ("s", "c2")
    assert runner.calls[1][-1] == "LockedHint"


def test_startup_unlocked_is_explicit_not_inferred_from_failure() -> None:
    value, _runner = source(
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b false\n"),
    )

    observation = asyncio.run(value.observe(request()))

    assert observation.state is LockState.UNLOCKED
    assert observation.failure_code is None


def test_malformed_locked_hint_fails_closed() -> None:
    value, _runner = source(
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b definitely\n"),
    )

    observation = asyncio.run(value.observe(request()))

    assert observation.state is LockState.UNKNOWN
    assert observation.failure_code is SessionSafetyFailureCode.MALFORMED


def test_unavailable_source_returns_unknown_not_unlocked() -> None:
    runner = FakeRunner([], available=False)
    value = LogindLockStateSource("c2", runner=runner, now=lambda: NOW)

    observation = asyncio.run(value.observe(request()))

    assert observation.state is LockState.UNKNOWN
    assert observation.failure_code is SessionSafetyFailureCode.UNAVAILABLE


def test_target_session_lock_unlock_signals_are_accepted() -> None:
    value, _runner = source(
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b false\n"),
    )
    asyncio.run(value.observe(request()))

    locked = value.signal_observation(
        LogindSignal(
            object_path="/org/freedesktop/login1/session/_32",
            interface="org.freedesktop.login1.Session",
            member="Lock",
        ),
        observed_at=NOW,
    )
    unlocked = value.signal_observation(
        LogindSignal(
            object_path="/org/freedesktop/login1/session/_32",
            interface="org.freedesktop.login1.Session",
            member="Unlock",
        ),
        observed_at=NOW,
    )

    assert locked is not None and locked.state is LockState.LOCKED
    assert unlocked is not None and unlocked.state is LockState.UNKNOWN
    assert unlocked.failure_code is SessionSafetyFailureCode.STALE


def test_unrelated_session_signal_is_ignored() -> None:
    value, _runner = source(
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b false\n"),
    )
    asyncio.run(value.observe(request()))

    observation = value.signal_observation(
        LogindSignal(
            object_path="/org/freedesktop/login1/session/_99",
            interface="org.freedesktop.login1.Session",
            member="Lock",
        )
    )

    assert observation is None


def test_disconnect_invalidates_cached_unlocked_state() -> None:
    value, _runner = source(
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b false\n"),
    )
    asyncio.run(value.observe(request()))

    observation = value.disconnected()

    assert observation.state is LockState.UNKNOWN
    assert observation.failure_code is SessionSafetyFailureCode.DISCONNECTED
    assert value.session_path is None


def test_reconnect_requeries_session_and_locked_hint_before_unlocking() -> None:
    value, runner = source(
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b false\n"),
        BusctlResult(0, b'o "/org/freedesktop/login1/session/_32"\n'),
        BusctlResult(0, b"b false\n"),
    )
    first = asyncio.run(value.observe(request()))
    assert first.state is LockState.UNLOCKED

    value.disconnected()
    second = asyncio.run(value.observe(request()))

    assert second.state is LockState.UNLOCKED
    assert len(runner.calls) == 4
    assert runner.calls[2][-2:] == ("s", "c2")
    assert runner.calls[3][-1] == "LockedHint"


def test_busctl_signal_parser_accepts_only_bounded_login1_session_members() -> None:
    signal = parse_busctl_signal(
        (
            "Type=signal Sender=:1.3",
            "Path=/org/freedesktop/login1/session/_32 "
            "Interface=org.freedesktop.login1.Session Member=Lock",
        )
    )
    malformed = parse_busctl_signal(
        (
            "Type=signal Sender=:1.3",
            "Path=/org/freedesktop/login1/session/_32 Interface=evil.Interface Member=Unlock",
        )
    )

    assert signal is not None and signal.member == "Lock"
    assert malformed is None
