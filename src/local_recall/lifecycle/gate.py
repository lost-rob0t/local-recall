from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TypeVar

from local_recall.domain.lifecycle import (
    CaptureGeneration,
    CaptureState,
    CaptureStateSnapshot,
    CaptureStateTransition,
    TransitionReason,
)
from local_recall.ports.clock import Clock

from .errors import CaptureGateClosed, CaptureGateOwnershipError, StaleCaptureGeneration

ResultT = TypeVar("ResultT")


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()


@dataclass(frozen=True, slots=True, repr=False)
class CaptureWorkPermit:
    generation: CaptureGeneration
    configuration_revision: str
    _cancel_event: threading.Event = field(repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def wait_cancelled(self, timeout: float | None = None) -> bool:
        return self._cancel_event.wait(timeout)

    def __repr__(self) -> str:
        return (
            f"CaptureWorkPermit(generation={self.generation!r}, "
            f"configuration_revision={self.configuration_revision!r}, "
            f"cancelled={self.cancelled})"
        )


class CaptureGate:
    """Thread-safe gate read by workers and mutated only by LifecycleActor."""

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or _SystemClock()
        self._state_lock = threading.RLock()
        self._commit_lock = threading.Lock()
        self._operations_changed = threading.Condition(self._state_lock)
        self._owner_thread_id: int | None = None
        self._state = CaptureState.OFF
        self._active_generation: CaptureGeneration | None = None
        self._draining_generation: CaptureGeneration | None = None
        self._generation_epoch = 0
        self._configuration_revision: str | None = None
        self._critical_dependencies_healthy = True
        self._cancel_events: dict[int, threading.Event] = {}
        self._in_flight: dict[int, int] = {}

    def snapshot(self) -> CaptureStateSnapshot:
        with self._state_lock:
            return CaptureStateSnapshot(
                state=self._state,
                generation=self._active_generation,
                observed_at=self._clock.now(),
                privacy_mode=self._state is CaptureState.PRIVACY,
                critical_dependencies_healthy=self._critical_dependencies_healthy,
            )

    @property
    def generation_epoch(self) -> int:
        with self._state_lock:
            return self._generation_epoch

    def run_preflight(
        self,
        generation: CaptureGeneration,
        operation: Callable[[CaptureWorkPermit], ResultT],
    ) -> ResultT:
        permit = self._acquire_preflight_operation(generation)
        try:
            return operation(permit)
        finally:
            self._release_operation(permit.generation)

    def run_capture(self, operation: Callable[[CaptureWorkPermit], ResultT]) -> ResultT:
        permit = self._acquire_capture_operation()
        try:
            return operation(permit)
        finally:
            self._release_operation(permit.generation)

    def run_persistence(
        self,
        generation: CaptureGeneration,
        operation: Callable[[CaptureWorkPermit], ResultT],
    ) -> ResultT:
        # The commit lock makes the final generation check and the commit atomic
        # with respect to stop/fault invalidation.
        with self._commit_lock:
            permit = self._acquire_persistence_operation(generation)
            try:
                return operation(permit)
            finally:
                self._release_operation(permit.generation)

    def require_current_generation(self, generation: CaptureGeneration) -> None:
        with self._state_lock:
            if self._active_generation != generation:
                raise StaleCaptureGeneration("capture generation is stale")
            if self._state not in {CaptureState.RECORDING, CaptureState.PAUSED}:
                raise CaptureGateClosed(f"capture gate is {self._state.value}")

    def wait_for_operations(self, generation: CaptureGeneration, timeout_seconds: float) -> bool:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        deadline = time.monotonic() + timeout_seconds
        with self._operations_changed:
            while self._in_flight.get(generation.value, 0) > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._operations_changed.wait(remaining)
            return True

    def bind_owner(self) -> None:
        thread_id = threading.get_ident()
        with self._state_lock:
            if self._owner_thread_id is None:
                self._owner_thread_id = thread_id
                return
            if self._owner_thread_id != thread_id:
                raise CaptureGateOwnershipError("capture gate already has a different owner")

    def release_owner(self) -> None:
        self._assert_owner()
        with self._state_lock:
            self._owner_thread_id = None

    def begin_start(
        self, reason: TransitionReason, configuration_revision: str
    ) -> tuple[CaptureGeneration, CaptureStateTransition]:
        self._assert_owner()
        with self._state_lock:
            if self._state is not CaptureState.OFF:
                raise ValueError("capture can start only from off")
            generation = self._next_generation_locked()
            self._active_generation = generation
            self._draining_generation = None
            self._configuration_revision = configuration_revision
            self._critical_dependencies_healthy = True
            self._cancel_events[generation.value] = threading.Event()
            transition = self._transition_locked(CaptureState.STARTING, generation, reason)
            return generation, transition

    def mark_recording(
        self, generation: CaptureGeneration, reason: TransitionReason
    ) -> CaptureStateTransition:
        self._assert_owner()
        with self._state_lock:
            self._require_active_locked(generation, CaptureState.STARTING)
            return self._transition_locked(CaptureState.RECORDING, generation, reason)

    def pause(self, reason: TransitionReason) -> CaptureStateTransition:
        self._assert_owner()
        with self._state_lock:
            generation = self._require_generation_locked(CaptureState.RECORDING)
            return self._transition_locked(CaptureState.PAUSED, generation, reason)

    def resume(self, reason: TransitionReason) -> CaptureStateTransition:
        self._assert_owner()
        with self._state_lock:
            generation = self._require_generation_locked(CaptureState.PAUSED)
            return self._transition_locked(CaptureState.RECORDING, generation, reason)

    def begin_stopping(
        self, reason: TransitionReason
    ) -> tuple[CaptureGeneration | None, CaptureStateTransition]:
        self._assert_owner()
        with self._commit_lock, self._state_lock:
            previous_generation = self._active_generation
            self._cancel_active_locked()
            if previous_generation is not None:
                self._draining_generation = previous_generation
            invalidation_generation = self._next_generation_locked()
            self._active_generation = None
            transition = self._transition_locked(
                CaptureState.STOPPING, invalidation_generation, reason
            )
            return previous_generation, transition

    def finish_off(self, reason: TransitionReason) -> CaptureStateTransition:
        self._assert_owner()
        with self._state_lock:
            generation = self._current_epoch_generation_locked()
            transition = self._transition_locked(CaptureState.OFF, generation, reason)
            self._active_generation = None
            self._draining_generation = None
            self._configuration_revision = None
            self._critical_dependencies_healthy = True
            stale_events = [
                value
                for value, event in self._cancel_events.items()
                if event.is_set() and self._in_flight.get(value, 0) == 0
            ]
            for value in stale_events:
                self._cancel_events.pop(value, None)
            return transition

    def fault(
        self, reason: TransitionReason
    ) -> tuple[CaptureGeneration | None, CaptureStateTransition]:
        self._assert_owner()
        with self._commit_lock, self._state_lock:
            previous_generation = self._active_generation or self._draining_generation
            self._cancel_active_locked()
            if self._active_generation is not None:
                self._draining_generation = self._active_generation
            invalidation_generation = self._next_generation_locked()
            self._active_generation = None
            self._critical_dependencies_healthy = False
            transition = self._transition_locked(
                CaptureState.FAULTED, invalidation_generation, reason
            )
            return previous_generation, transition

    def configuration_revision_for_audit(self) -> str | None:
        with self._state_lock:
            return self._configuration_revision

    def _acquire_preflight_operation(self, generation: CaptureGeneration) -> CaptureWorkPermit:
        with self._state_lock:
            self._require_active_locked(generation, CaptureState.STARTING)
            return self._register_operation_locked(generation)

    def _acquire_capture_operation(self) -> CaptureWorkPermit:
        with self._state_lock:
            if self._state is not CaptureState.RECORDING:
                raise CaptureGateClosed(f"capture gate is {self._state.value}")
            generation = self._require_generation_locked(CaptureState.RECORDING)
            return self._register_operation_locked(generation)

    def _acquire_persistence_operation(self, generation: CaptureGeneration) -> CaptureWorkPermit:
        with self._state_lock:
            if self._state not in {CaptureState.RECORDING, CaptureState.PAUSED}:
                raise CaptureGateClosed(f"persistence gate is {self._state.value}")
            if self._active_generation != generation:
                raise StaleCaptureGeneration("persistence generation is stale")
            return self._register_operation_locked(generation)

    def _register_operation_locked(self, generation: CaptureGeneration) -> CaptureWorkPermit:
        cancel_event = self._cancel_events.get(generation.value)
        if cancel_event is None or cancel_event.is_set():
            raise StaleCaptureGeneration("capture generation is stale")
        revision = self._configuration_revision
        if revision is None:
            raise RuntimeError("active capture has no configuration revision")
        self._in_flight[generation.value] = self._in_flight.get(generation.value, 0) + 1
        return CaptureWorkPermit(generation, revision, cancel_event)

    def _release_operation(self, generation: CaptureGeneration) -> None:
        with self._operations_changed:
            current = self._in_flight.get(generation.value, 0)
            if current <= 1:
                self._in_flight.pop(generation.value, None)
                if self._active_generation != generation:
                    self._cancel_events.pop(generation.value, None)
            else:
                self._in_flight[generation.value] = current - 1
            self._operations_changed.notify_all()

    def _assert_owner(self) -> None:
        if self._owner_thread_id != threading.get_ident():
            raise CaptureGateOwnershipError(
                "capture lifecycle transitions are owned by LifecycleActor"
            )

    def _require_active_locked(self, generation: CaptureGeneration, state: CaptureState) -> None:
        if self._state is not state or self._active_generation != generation:
            raise StaleCaptureGeneration("capture generation or state is stale")

    def _require_generation_locked(self, state: CaptureState) -> CaptureGeneration:
        if self._state is not state or self._active_generation is None:
            raise ValueError(f"capture state must be {state.value}")
        return self._active_generation

    def _next_generation_locked(self) -> CaptureGeneration:
        self._generation_epoch += 1
        return CaptureGeneration(self._generation_epoch)

    def _current_epoch_generation_locked(self) -> CaptureGeneration:
        if self._generation_epoch == 0:
            return self._next_generation_locked()
        return CaptureGeneration(self._generation_epoch)

    def _cancel_active_locked(self) -> None:
        if self._active_generation is None:
            return
        cancel_event = self._cancel_events.get(self._active_generation.value)
        if cancel_event is not None:
            cancel_event.set()

    def _transition_locked(
        self,
        current: CaptureState,
        generation: CaptureGeneration,
        reason: TransitionReason,
    ) -> CaptureStateTransition:
        transition = CaptureStateTransition(
            previous=self._state,
            current=current,
            generation=generation,
            reason=reason,
            occurred_at=self._clock.now(),
        )
        self._state = current
        return transition
