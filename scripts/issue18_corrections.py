from __future__ import annotations

from pathlib import Path


def replace(path: str, old: str, new: str, *, count: int = 1) -> None:
    target = Path(path)
    text = target.read_text()
    if text.count(old) != count:
        raise SystemExit(f"expected {count} correction target(s) in {path}")
    target.write_text(text.replace(old, new))


replace(
    "src/local_recall/lifecycle/actor.py",
    """            if self._automatic_pause_reason is TransitionReason.SESSION_LOCKED:\n                if command.reason is TransitionReason.IDLE:\n                    return self._result(True, False, \"stronger_safety_block_active\")\n""",
    """            if (\n                self._automatic_pause_reason is TransitionReason.SESSION_LOCKED\n                and command.reason is TransitionReason.IDLE\n            ):\n                return self._result(True, False, \"stronger_safety_block_active\")\n""",
)
replace(
    "src/local_recall/session/safety.py",
    """        if self.idle_seconds is not None:\n            if (\n                not math.isfinite(self.idle_seconds)\n                or not 0.0 <= self.idle_seconds <= _MAX_IDLE_SECONDS\n            ):\n                raise ValueError(\"idle_seconds is outside the supported range\")\n""",
    """        if self.idle_seconds is not None and (\n            not math.isfinite(self.idle_seconds)\n            or not 0.0 <= self.idle_seconds <= _MAX_IDLE_SECONDS\n        ):\n            raise ValueError(\"idle_seconds is outside the supported range\")\n""",
)
replace(
    "src/local_recall/session/safety.py",
    """    def replace_idle_settings(self, settings: IdleSettings) -> None:\n        with self._lock_guard:\n            self._settings = settings\n            self._reconcile()\n""",
    """    def replace_idle_settings(self, settings: IdleSettings) -> None:\n        with self._lock_guard:\n            previous = self._idle\n            self._settings = settings\n            if self._idle.idle_seconds is not None:\n                self._idle, conflict = self._resolve_idle((self._idle,))\n                if conflict:\n                    self._last_failure = SessionSafetyFailureCode.SOURCE_CONFLICT\n                self._update_resume_latches(previous, self._idle)\n            self._reconcile()\n""",
)
replace(
    "tests/integration/test_session_safety.py",
    "actor_ref, gate, _source, coordinator, _audit = start_actor(enabled=True)",
    "actor_ref, _gate, _source, coordinator, _audit = start_actor(enabled=True)",
)
replace(
    "tests/integration/test_session_safety.py",
    "boundary.downstream(operation, context, lambda: calls.append(operation.value))",
    "boundary.downstream(operation, context, lambda: calls.append(\"downstream\"))",
)
replace(
    "tests/integration/test_session_safety.py",
    """NOW = datetime(2026, 8, 12, 20, 0, tzinfo=UTC)\n\n\ndef policy_engine()""",
    """NOW = datetime(2026, 8, 12, 20, 0, tzinfo=UTC)\n\n\nclass FixedClock:\n    def now(self) -> datetime:\n        return NOW\n\n    def monotonic_ns(self) -> int:\n        return 1_000_000_000\n\n\ndef policy_engine()""",
)
replace(
    "tests/integration/test_session_safety.py",
    """            lifecycle=LifecycleAutomaticCaptureBlockSink(actor_ref),\n        )""",
    """            lifecycle=LifecycleAutomaticCaptureBlockSink(actor_ref),\n            clock=FixedClock(),\n        )""",
    count=2,
)
replace(
    "tests/unit/session/test_logind_lock.py",
    '            "Path=/org/freedesktop/login1/session/_32 Interface=org.freedesktop.login1.Session Member=Lock",\n',
    '            "Path=/org/freedesktop/login1/session/_32 "\n            "Interface=org.freedesktop.login1.Session Member=Lock",\n',
)
replace(
    "tests/unit/session/test_logind_lock.py",
    "calls: list[tuple[str, ...]] = field(default_factory=list, init=False)",
    "calls: list[tuple[str, ...]] = field(\n        default_factory=lambda: list[tuple[str, ...]](), init=False\n    )",
)
replace(
    "tests/unit/session/test_session_safety.py",
    "calls: list[tuple[bool, TransitionReason]] = field(default_factory=list, init=False)",
    "calls: list[tuple[bool, TransitionReason]] = field(\n        default_factory=lambda: list[tuple[bool, TransitionReason]](), init=False\n    )",
)
replace(
    "tests/unit/session/test_session_safety.py",
    """    value, policy, lifecycle, _clock = controller(settings=settings)\n    value.apply_idle(())\n    lifecycle.calls.clear()\n\n    value.apply_lock(lock(LockState.LOCKED))\n""",
    """    value, policy, lifecycle, _clock = controller(settings=settings)\n    value.apply_lock(lock(LockState.UNLOCKED))\n    value.apply_idle(())\n    lifecycle.calls.clear()\n\n    value.apply_lock(lock(LockState.LOCKED))\n""",
)
