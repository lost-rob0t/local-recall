from __future__ import annotations

import asyncio
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, cast, runtime_checkable

import pykka

from local_recall.config.models import IdleResumeBehavior, IdleSettings
from local_recall.domain.lifecycle import CaptureGeneration, TransitionReason
from local_recall.domain.policy import PolicyStatus
from local_recall.lifecycle.actor import LifecycleActor
from local_recall.lifecycle.messages import (
    LifecycleCommandResult,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
    SetAutomaticCaptureBlock,
)
from local_recall.lifecycle.ports import LifecyclePreflight
from local_recall.ports.clock import Clock

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_MAX_IDLE_SECONDS = 7 * 24 * 60 * 60.0
_DEFAULT_LOCK_TTL_SECONDS = 5.0


class LockState(StrEnum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    UNKNOWN = "unknown"


class IdleState(StrEnum):
    IDLE = "idle"
    ACTIVE = "active"
    UNKNOWN = "unknown"


class SessionSafetyFailureCode(StrEnum):
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    DISCONNECTED = "disconnected"
    MALFORMED = "malformed"
    STALE = "stale"
    PERMISSION_DENIED = "permission-denied"
    WRONG_SESSION = "wrong-session"
    SOURCE_CONFLICT = "source-conflict"
    LIFECYCLE_REJECTED = "lifecycle-rejected"


class SessionSafetyHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True, repr=False)
class LockObservation:
    state: LockState
    observed_at: datetime
    source_id: str
    source_revision: str
    failure_code: SessionSafetyFailureCode | None = None

    def __post_init__(self) -> None:
        _validate_observation(self.observed_at, self.source_id, self.source_revision)
        if self.failure_code is not None and self.state is not LockState.UNKNOWN:
            raise ValueError("failed lock observations must be unknown")

    def __repr__(self) -> str:
        return (
            "LockObservation("
            f"state={self.state.value!r}, source_id={self.source_id!r}, "
            f"source_revision={self.source_revision!r}, failure_code={self.failure_code!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class IdleObservation:
    state: IdleState
    observed_at: datetime
    source_id: str
    source_revision: str
    idle_seconds: float | None = None
    failure_code: SessionSafetyFailureCode | None = None

    def __post_init__(self) -> None:
        _validate_observation(self.observed_at, self.source_id, self.source_revision)
        if self.idle_seconds is not None and (
            not math.isfinite(self.idle_seconds)
            or not 0.0 <= self.idle_seconds <= _MAX_IDLE_SECONDS
        ):
            raise ValueError("idle_seconds is outside the supported range")
        if self.failure_code is not None and self.state is not IdleState.UNKNOWN:
            raise ValueError("failed idle observations must be unknown")

    def __repr__(self) -> str:
        return (
            "IdleObservation("
            f"state={self.state.value!r}, source_id={self.source_id!r}, "
            f"source_revision={self.source_revision!r}, "
            f"has_idle_seconds={self.idle_seconds is not None}, "
            f"failure_code={self.failure_code!r})"
        )


@dataclass(frozen=True, slots=True)
class SessionSafetyState:
    lock: LockObservation
    idle: IdleObservation
    idle_pause_enabled: bool = True

    @property
    def capture_blocked(self) -> bool:
        return self.lock.state is not LockState.UNLOCKED or (
            self.idle_pause_enabled and self.idle.state is IdleState.IDLE
        )

    @property
    def effective_reason(self) -> str | None:
        if self.lock.state is LockState.LOCKED:
            return "locked"
        if self.lock.state is LockState.UNKNOWN:
            return "lock-unknown"
        if self.idle_pause_enabled and self.idle.state is IdleState.IDLE:
            return "idle"
        return None


@dataclass(frozen=True, slots=True)
class SessionSafetyStatus:
    lock_state: LockState
    idle_state: IdleState
    lock_source_id: str
    idle_source_id: str
    health: SessionSafetyHealth
    idle_threshold_seconds: float
    current_generation: int | None
    last_failure_code: SessionSafetyFailureCode | None

    def as_dict(self) -> dict[str, object]:
        return {
            "lock_state": self.lock_state.value,
            "idle_state": self.idle_state.value,
            "lock_source": self.lock_source_id,
            "idle_source": self.idle_source_id,
            "health": self.health.value,
            "idle_threshold_seconds": self.idle_threshold_seconds,
            "current_generation": self.current_generation,
            "last_failure_code": (
                None if self.last_failure_code is None else self.last_failure_code.value
            ),
        }


@dataclass(frozen=True, slots=True)
class SessionSafetyAuditEvent:
    control: str
    previous_state: str
    current_state: str
    source_id: str
    generation: int | None
    reason_code: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.control not in {"lock", "idle"}:
            raise ValueError("unsupported safety audit control")
        if self.previous_state not in {"locked", "unlocked", "unknown", "idle", "active"}:
            raise ValueError("unsupported previous safety state")
        if self.current_state not in {"locked", "unlocked", "unknown", "idle", "active"}:
            raise ValueError("unsupported current safety state")
        if not _IDENTIFIER.fullmatch(self.source_id):
            raise ValueError("invalid safety source identifier")
        if self.generation is not None and self.generation <= 0:
            raise ValueError("safety audit generation must be positive")
        if not _IDENTIFIER.fullmatch(self.reason_code):
            raise ValueError("invalid safety audit reason code")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("safety audit timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class SafetyObservationRequest:
    generation: CaptureGeneration
    deadline_monotonic_ns: int

    def __post_init__(self) -> None:
        if self.deadline_monotonic_ns <= 0:
            raise ValueError("safety observation deadline must be positive")


@runtime_checkable
class LockStateSource(Protocol):
    @property
    def source_id(self) -> str: ...

    async def observe(self, request: SafetyObservationRequest) -> LockObservation: ...


@runtime_checkable
class IdleStateSource(Protocol):
    @property
    def source_id(self) -> str: ...

    async def observe(self, request: SafetyObservationRequest) -> IdleObservation: ...


@runtime_checkable
class SessionLockPolicy(Protocol):
    def set_session_locked(self, locked: bool) -> None: ...

    def status(self) -> PolicyStatus: ...


@runtime_checkable
class AutomaticCaptureBlockSink(Protocol):
    def apply(self, *, blocked: bool, reason: TransitionReason) -> LifecycleCommandResult: ...


@runtime_checkable
class SessionSafetyAuditSink(Protocol):
    def emit(self, event: SessionSafetyAuditEvent) -> None: ...


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()


class LifecycleAutomaticCaptureBlockSink:
    def __init__(
        self,
        actor_ref: pykka.ActorRef[LifecycleActor],
        *,
        timeout_seconds: float = 2.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("lifecycle safety timeout must be positive")
        self._actor_ref = actor_ref
        self._timeout_seconds = timeout_seconds

    def apply(self, *, blocked: bool, reason: TransitionReason) -> LifecycleCommandResult:
        return cast(
            LifecycleCommandResult,
            self._actor_ref.ask(
                SetAutomaticCaptureBlock(blocked=blocked, reason=reason),
                timeout=self._timeout_seconds,
            ),
        )


class SessionSafetyController:
    def __init__(
        self,
        *,
        policy: SessionLockPolicy,
        lifecycle: AutomaticCaptureBlockSink,
        idle_settings: IdleSettings | None = None,
        idle_source_order: tuple[str, ...] = ("activitywatch", "xorg-idle"),
        audit_sink: SessionSafetyAuditSink | None = None,
        clock: Clock | None = None,
        lock_state_ttl_seconds: float = _DEFAULT_LOCK_TTL_SECONDS,
    ) -> None:
        if lock_state_ttl_seconds <= 0 or lock_state_ttl_seconds > 300:
            raise ValueError("lock_state_ttl_seconds must be between 0 and 300")
        if len(set(idle_source_order)) != len(idle_source_order):
            raise ValueError("idle source order must be unique")
        if any(not _IDENTIFIER.fullmatch(item) for item in idle_source_order):
            raise ValueError("idle source identifiers are invalid")
        self._policy = policy
        self._lifecycle = lifecycle
        self._settings = idle_settings or IdleSettings()
        self._source_order = idle_source_order
        self._audit_sink = audit_sink
        self._clock: Clock = clock or _SystemClock()
        self._lock_state_ttl_ns = int(lock_state_ttl_seconds * 1_000_000_000)
        now = self._clock.now()
        self._lock = LockObservation(
            state=LockState.UNKNOWN,
            observed_at=now,
            source_id="startup",
            source_revision="startup-v1",
            failure_code=SessionSafetyFailureCode.STALE,
        )
        self._idle = IdleObservation(
            state=IdleState.UNKNOWN,
            observed_at=now,
            source_id="none",
            source_revision="none-v1",
            failure_code=SessionSafetyFailureCode.UNAVAILABLE,
        )
        self._lock_received_ns = self._clock.monotonic_ns()
        self._active_since_ns: int | None = None
        self._manual_idle_latch = False
        self._idle_uncertain_latch = False
        self._blocked = False
        self._block_reason: TransitionReason | None = None
        self._last_generation: int | None = None
        self._last_failure = SessionSafetyFailureCode.STALE
        self._lock_guard = threading.RLock()
        self._policy.set_session_locked(True)

    @property
    def capture_blocked(self) -> bool:
        with self._lock_guard:
            return self._blocked or self._desired_block_reason() is not None

    @property
    def block_reason(self) -> TransitionReason | None:
        with self._lock_guard:
            return self._block_reason or self._desired_block_reason()

    @property
    def idle_settings(self) -> IdleSettings:
        with self._lock_guard:
            return self._settings

    def apply_lock(self, observation: LockObservation) -> None:
        with self._lock_guard:
            normalized = self._normalize_lock(observation)
            previous = self._lock
            self._lock = normalized
            self._lock_received_ns = self._clock.monotonic_ns()
            if normalized.failure_code is not None:
                self._last_failure = normalized.failure_code
            self._policy.set_session_locked(normalized.state is not LockState.UNLOCKED)
            if previous.state is not normalized.state:
                self._emit_audit(
                    "lock",
                    previous.state.value,
                    normalized.state.value,
                    normalized.source_id,
                    "lock-state",
                )
            self._reconcile()

    def apply_idle(self, observations: tuple[IdleObservation, ...]) -> None:
        with self._lock_guard:
            previous = self._idle
            normalized, conflict = self._resolve_idle(observations)
            self._idle = normalized
            if normalized.failure_code is not None:
                self._last_failure = normalized.failure_code
            if conflict:
                self._last_failure = SessionSafetyFailureCode.SOURCE_CONFLICT
            self._update_resume_latches(previous, normalized)
            if previous.state is not normalized.state:
                self._emit_audit(
                    "idle",
                    previous.state.value,
                    normalized.state.value,
                    normalized.source_id,
                    "idle-state",
                )
            self._reconcile()

    def replace_idle_settings(self, settings: IdleSettings) -> None:
        with self._lock_guard:
            previous = self._idle
            self._settings = settings
            if self._idle.idle_seconds is not None:
                self._idle, conflict = self._resolve_idle((self._idle,))
                if conflict:
                    self._last_failure = SessionSafetyFailureCode.SOURCE_CONFLICT
                self._update_resume_latches(previous, self._idle)
            self._reconcile()

    def acknowledge_idle_resume(self) -> None:
        with self._lock_guard:
            self._manual_idle_latch = False
            self._reconcile()

    def refresh(self) -> None:
        with self._lock_guard:
            if self._lock.state is LockState.UNLOCKED:
                elapsed = self._clock.monotonic_ns() - self._lock_received_ns
                if elapsed > self._lock_state_ttl_ns:
                    previous = self._lock
                    self._lock = LockObservation(
                        state=LockState.UNKNOWN,
                        observed_at=self._clock.now(),
                        source_id=previous.source_id,
                        source_revision=previous.source_revision,
                        failure_code=SessionSafetyFailureCode.STALE,
                    )
                    self._last_failure = SessionSafetyFailureCode.STALE
                    self._policy.set_session_locked(True)
                    self._emit_audit(
                        "lock",
                        previous.state.value,
                        LockState.UNKNOWN.value,
                        previous.source_id,
                        "lock-stale",
                    )
            self._reconcile()

    def status(self) -> SessionSafetyStatus:
        with self._lock_guard:
            degraded = (
                self._lock.state is LockState.UNKNOWN
                or (self._settings.enabled and self._idle.failure_code is not None)
                or self._last_failure is SessionSafetyFailureCode.SOURCE_CONFLICT
            )
            return SessionSafetyStatus(
                lock_state=self._lock.state,
                idle_state=self._idle.state,
                lock_source_id=self._lock.source_id,
                idle_source_id=self._idle.source_id,
                health=SessionSafetyHealth.DEGRADED if degraded else SessionSafetyHealth.HEALTHY,
                idle_threshold_seconds=self._settings.threshold_seconds,
                current_generation=self._last_generation,
                last_failure_code=self._last_failure if degraded else None,
            )

    def _normalize_lock(self, observation: LockObservation) -> LockObservation:
        now = self._clock.now()
        age = (now - observation.observed_at).total_seconds()
        if age < -2.0:
            return LockObservation(
                state=LockState.UNKNOWN,
                observed_at=now,
                source_id=observation.source_id,
                source_revision=observation.source_revision,
                failure_code=SessionSafetyFailureCode.MALFORMED,
            )
        if observation.state is LockState.UNLOCKED and age > self._lock_state_ttl_ns / 1e9:
            return LockObservation(
                state=LockState.UNKNOWN,
                observed_at=now,
                source_id=observation.source_id,
                source_revision=observation.source_revision,
                failure_code=SessionSafetyFailureCode.STALE,
            )
        return observation

    def _resolve_idle(
        self, observations: tuple[IdleObservation, ...]
    ) -> tuple[IdleObservation, bool]:
        return resolve_idle_observations(
            observations,
            settings=self._settings,
            source_order=self._source_order,
            now=self._clock.now(),
        )

    def _update_resume_latches(self, previous: IdleObservation, current: IdleObservation) -> None:
        if current.state is IdleState.IDLE:
            self._active_since_ns = None
            self._idle_uncertain_latch = False
            return
        if current.state is IdleState.UNKNOWN:
            if self._blocked and self._block_reason is TransitionReason.IDLE:
                self._idle_uncertain_latch = True
            return
        self._idle_uncertain_latch = False
        if previous.state is not IdleState.IDLE:
            return
        if self._settings.resume_behavior is IdleResumeBehavior.MANUAL:
            self._manual_idle_latch = True
        elif self._settings.resume_behavior is IdleResumeBehavior.ACTIVE_GRACE:
            self._active_since_ns = self._clock.monotonic_ns()

    def _idle_blocked(self) -> bool:
        if not self._settings.enabled or not self._settings.pause_capture:
            return False
        if self._idle.state is IdleState.IDLE:
            return True
        if self._idle_uncertain_latch:
            return True
        if self._settings.resume_behavior is IdleResumeBehavior.MANUAL and self._manual_idle_latch:
            return True
        if (
            self._settings.resume_behavior is IdleResumeBehavior.ACTIVE_GRACE
            and self._active_since_ns is not None
        ):
            elapsed = self._clock.monotonic_ns() - self._active_since_ns
            if elapsed < int(self._settings.active_grace_seconds * 1_000_000_000):
                return True
            self._active_since_ns = None
        return False

    def _desired_block_reason(self) -> TransitionReason | None:
        if self._lock.state is not LockState.UNLOCKED:
            return TransitionReason.SESSION_LOCKED
        if self._idle_blocked():
            return TransitionReason.IDLE
        return None

    def _reconcile(self) -> None:
        desired = self._desired_block_reason()
        if desired is not None:
            if self._blocked and self._block_reason is desired:
                return
            self._apply_lifecycle(True, desired)
            return
        if not self._blocked:
            self._block_reason = None
            return
        if self._policy.status().privacy_mode:
            return
        release_reason = (
            TransitionReason.SESSION_UNLOCKED
            if self._block_reason is TransitionReason.SESSION_LOCKED
            else TransitionReason.ACTIVE
        )
        self._apply_lifecycle(False, release_reason)

    def _apply_lifecycle(self, blocked: bool, reason: TransitionReason) -> None:
        try:
            result = self._lifecycle.apply(blocked=blocked, reason=reason)
        except Exception:
            self._last_failure = SessionSafetyFailureCode.LIFECYCLE_REJECTED
            self._policy.set_session_locked(True)
            self._blocked = True
            self._block_reason = TransitionReason.SESSION_LOCKED
            return
        generation = result.snapshot.generation
        self._last_generation = None if generation is None else generation.value
        if not result.accepted:
            self._last_failure = SessionSafetyFailureCode.LIFECYCLE_REJECTED
            self._policy.set_session_locked(True)
            self._blocked = True
            self._block_reason = TransitionReason.SESSION_LOCKED
            return
        self._blocked = blocked
        self._block_reason = reason if blocked else None

    def _emit_audit(
        self,
        control: str,
        previous_state: str,
        current_state: str,
        source_id: str,
        reason_code: str,
    ) -> None:
        sink = self._audit_sink
        if sink is None:
            return
        try:
            sink.emit(
                SessionSafetyAuditEvent(
                    control=control,
                    previous_state=previous_state,
                    current_state=current_state,
                    source_id=source_id,
                    generation=self._last_generation,
                    reason_code=reason_code,
                    occurred_at=self._clock.now(),
                )
            )
        except Exception:
            self._last_failure = SessionSafetyFailureCode.LIFECYCLE_REJECTED
            self._policy.set_session_locked(True)
            self._apply_lifecycle(True, TransitionReason.SESSION_LOCKED)


class SessionSafetyPreflight:
    def __init__(
        self,
        *,
        base: LifecyclePreflight,
        policy: SessionLockPolicy,
        lock_source: LockStateSource,
        idle_settings: IdleSettings | None = None,
        idle_sources: tuple[IdleStateSource, ...] = (),
        idle_source_order: tuple[str, ...] = ("activitywatch", "xorg-idle"),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if len({source.source_id for source in idle_sources}) != len(idle_sources):
            raise ValueError("idle sources must be unique")
        if len(set(idle_source_order)) != len(idle_source_order):
            raise ValueError("idle source order must be unique")
        self._base = base
        self._policy = policy
        self._lock_source = lock_source
        self._idle_settings = idle_settings or IdleSettings()
        self._idle_sources = idle_sources
        self._source_order = idle_source_order
        self._now = now or (lambda: datetime.now(UTC))

    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        observation_request = SafetyObservationRequest(
            generation=request.generation,
            deadline_monotonic_ns=request.deadline_monotonic_ns,
        )
        try:
            lock_observation, idle_observations = asyncio.run(self._collect(observation_request))
        except Exception:
            lock_observation = LockObservation(
                state=LockState.UNKNOWN,
                observed_at=self._now(),
                source_id=self._lock_source.source_id,
                source_revision="source-v1",
                failure_code=SessionSafetyFailureCode.UNAVAILABLE,
            )
            idle_observations = ()

        self._policy.set_session_locked(lock_observation.state is not LockState.UNLOCKED)
        base_result = self._base.check(request)
        if not base_result.ready:
            return base_result
        if lock_observation.state is not LockState.UNLOCKED:
            return LifecyclePreflightResult.success(
                start_paused_reason=TransitionReason.SESSION_LOCKED
            )
        if self._idle_settings.enabled and self._idle_settings.pause_capture:
            idle, _conflict = resolve_idle_observations(
                idle_observations,
                settings=self._idle_settings,
                source_order=self._source_order,
                now=self._now(),
            )
            if idle.state is IdleState.IDLE:
                return LifecyclePreflightResult.success(start_paused_reason=TransitionReason.IDLE)
        return base_result

    async def _collect(
        self, request: SafetyObservationRequest
    ) -> tuple[LockObservation, tuple[IdleObservation, ...]]:
        lock_task = asyncio.create_task(self._lock_source.observe(request))
        idle_tasks = tuple(
            asyncio.create_task(source.observe(request)) for source in self._idle_sources
        )
        try:
            lock = await lock_task
        except asyncio.CancelledError:
            raise
        except Exception:
            lock = LockObservation(
                state=LockState.UNKNOWN,
                observed_at=self._now(),
                source_id=self._lock_source.source_id,
                source_revision="source-v1",
                failure_code=SessionSafetyFailureCode.UNAVAILABLE,
            )
        idle: list[IdleObservation] = []
        for source, task in zip(self._idle_sources, idle_tasks, strict=True):
            try:
                idle.append(await task)
            except asyncio.CancelledError:
                raise
            except Exception:
                idle.append(
                    IdleObservation(
                        state=IdleState.UNKNOWN,
                        observed_at=self._now(),
                        source_id=source.source_id,
                        source_revision="source-v1",
                        failure_code=SessionSafetyFailureCode.UNAVAILABLE,
                    )
                )
        return lock, tuple(idle)


def resolve_idle_observations(
    observations: tuple[IdleObservation, ...],
    *,
    settings: IdleSettings,
    source_order: tuple[str, ...],
    now: datetime,
) -> tuple[IdleObservation, bool]:
    if not observations:
        return (
            IdleObservation(
                state=IdleState.UNKNOWN,
                observed_at=now,
                source_id="none",
                source_revision="none-v1",
                failure_code=SessionSafetyFailureCode.UNAVAILABLE,
            ),
            False,
        )
    rank = {source_id: index for index, source_id in enumerate(source_order)}
    normalized: list[IdleObservation] = []
    for observation in observations:
        age = (now - observation.observed_at).total_seconds()
        if age < -2.0 or age > settings.max_observation_age_seconds:
            normalized.append(
                IdleObservation(
                    state=IdleState.UNKNOWN,
                    observed_at=now,
                    source_id=observation.source_id,
                    source_revision=observation.source_revision,
                    failure_code=(
                        SessionSafetyFailureCode.MALFORMED
                        if age < -2.0
                        else SessionSafetyFailureCode.STALE
                    ),
                )
            )
            continue
        if observation.idle_seconds is None:
            normalized.append(observation)
            continue
        normalized.append(
            IdleObservation(
                state=(
                    IdleState.IDLE
                    if observation.idle_seconds >= settings.threshold_seconds
                    else IdleState.ACTIVE
                ),
                observed_at=observation.observed_at,
                source_id=observation.source_id,
                source_revision=observation.source_revision,
                idle_seconds=observation.idle_seconds,
            )
        )
    current = tuple(item for item in normalized if item.state is not IdleState.UNKNOWN)
    has_idle = any(item.state is IdleState.IDLE for item in current)
    has_active = any(item.state is IdleState.ACTIVE for item in current)
    conflict = has_idle and has_active
    candidates = (
        tuple(item for item in current if item.state is IdleState.IDLE)
        if has_idle
        else tuple(item for item in current if item.state is IdleState.ACTIVE)
        if has_active
        else tuple(normalized)
    )
    selected = min(
        candidates,
        key=lambda item: (rank.get(item.source_id, len(rank)), item.source_id),
    )
    return selected, conflict


def _validate_observation(observed_at: datetime, source_id: str, source_revision: str) -> None:
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("session safety observation must be timezone-aware")
    if not _IDENTIFIER.fullmatch(source_id):
        raise ValueError("invalid session safety source identifier")
    if not _IDENTIFIER.fullmatch(source_revision):
        raise ValueError("invalid session safety source revision")
