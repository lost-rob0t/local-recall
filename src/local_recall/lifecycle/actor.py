from __future__ import annotations

import time
from datetime import UTC, datetime
from types import TracebackType

import pykka

from local_recall.domain.lifecycle import (
    CaptureGeneration,
    CaptureState,
    CaptureStateTransition,
    TransitionReason,
)
from local_recall.ports.clock import Clock

from .errors import CaptureGateClosed, StaleCaptureGeneration
from .gate import CaptureGate
from .messages import (
    CompleteLifecyclePreflight,
    FaultCapture,
    GetLifecycleSnapshot,
    LifecycleAuditEvent,
    LifecycleCommandResult,
    LifecycleFaultCode,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
    PauseCapture,
    ResumeCapture,
    RunLifecyclePreflight,
    SetAutomaticCaptureBlock,
    StartCapture,
    StopCapture,
)
from .ports import (
    CaptureWorkCoordinator,
    LifecycleAuditSink,
    LifecycleConfigurationSource,
    LifecyclePreflight,
)


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()


class _LifecyclePreflightActor(pykka.ThreadingActor):
    """Runs potentially blocking preflight work outside the lifecycle owner inbox."""

    def __init__(
        self,
        *,
        gate: CaptureGate,
        preflight: LifecyclePreflight,
        lifecycle_ref: pykka.ActorRef[LifecycleActor],
        clock: Clock,
    ) -> None:
        super().__init__()
        self._gate = gate
        self._preflight = preflight
        self._lifecycle_ref = lifecycle_ref
        self._clock = clock

    def on_receive(self, message: object) -> None:
        if not isinstance(message, RunLifecyclePreflight):
            return
        try:
            result = self._gate.run_preflight(
                message.generation,
                lambda permit: self._preflight.check(
                    LifecyclePreflightRequest(
                        configuration=message.configuration,
                        generation=message.generation,
                        deadline_monotonic_ns=message.deadline_monotonic_ns,
                        cancellation=permit,
                    )
                ),
            )
        except CaptureGateClosed, StaleCaptureGeneration:
            return
        except Exception:
            result = LifecyclePreflightResult.failure(LifecycleFaultCode.PREFLIGHT_FAILURE)

        if self._clock.monotonic_ns() > message.deadline_monotonic_ns:
            result = LifecyclePreflightResult.failure(LifecycleFaultCode.PREFLIGHT_TIMEOUT)

        try:
            self._lifecycle_ref.tell(
                CompleteLifecyclePreflight(
                    generation=message.generation,
                    result=result,
                    reason=message.reason,
                )
            )
        except pykka.ActorDeadError:
            return


class LifecycleActor(pykka.ThreadingActor):
    """Sole owner of authoritative capture lifecycle transitions."""

    def __init__(
        self,
        *,
        gate: CaptureGate,
        configuration_source: LifecycleConfigurationSource,
        preflight: LifecyclePreflight,
        work_coordinator: CaptureWorkCoordinator,
        audit_sink: LifecycleAuditSink,
        clock: Clock | None = None,
        preflight_timeout_seconds: float = 5.0,
        stop_timeout_seconds: float = 5.0,
    ) -> None:
        super().__init__()
        if preflight_timeout_seconds <= 0:
            raise ValueError("preflight_timeout_seconds must be positive")
        if stop_timeout_seconds <= 0:
            raise ValueError("stop_timeout_seconds must be positive")
        self._gate = gate
        self._configuration_source = configuration_source
        self._preflight = preflight
        self._work_coordinator = work_coordinator
        self._audit_sink = audit_sink
        self._clock = clock or _SystemClock()
        self._preflight_timeout_seconds = preflight_timeout_seconds
        self._stop_timeout_seconds = stop_timeout_seconds
        self._preflight_ref: pykka.ActorRef[_LifecyclePreflightActor] | None = None
        self._manual_pause = False
        self._automatic_pause_reason: TransitionReason | None = None

    def on_start(self) -> None:
        self._gate.bind_owner()
        self._preflight_ref = _LifecyclePreflightActor.start(
            gate=self._gate,
            preflight=self._preflight,
            lifecycle_ref=self.actor_ref,
            clock=self._clock,
        )
        try:
            configuration = self._configuration_source.snapshot()
        except Exception:
            self._enter_fault(LifecycleFaultCode.PREFLIGHT_FAILURE)
            return
        if configuration.configuration.capture_permitted:
            self._handle_start(StartCapture(reason=TransitionReason.STARTUP_OPT_IN))

    def on_receive(self, message: object) -> object:
        if isinstance(message, GetLifecycleSnapshot):
            return self._gate.snapshot()
        if isinstance(message, StartCapture):
            return self._handle_start(message)
        if isinstance(message, PauseCapture):
            return self._handle_pause(message)
        if isinstance(message, ResumeCapture):
            return self._handle_resume(message)
        if isinstance(message, SetAutomaticCaptureBlock):
            return self._handle_automatic_block(message)
        if isinstance(message, StopCapture):
            return self._handle_stop(message)
        if isinstance(message, FaultCapture):
            return self._handle_fault(message)
        if isinstance(message, CompleteLifecyclePreflight):
            return self._handle_preflight_complete(message)
        del message
        return self._enter_fault(LifecycleFaultCode.ACTOR_FAILURE)

    def on_stop(self) -> None:
        try:
            if self._gate.snapshot().state is not CaptureState.OFF:
                result = self._handle_stop(StopCapture(reason=TransitionReason.SHUTDOWN))
                if result.snapshot.state not in {CaptureState.OFF, CaptureState.FAULTED}:
                    self._enter_fault(LifecycleFaultCode.SHUTDOWN_FAILURE)
        finally:
            self._stop_preflight_actor()
            self._gate.release_owner()

    def on_failure(
        self,
        exception_type: type[BaseException] | None,
        exception_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exception_type, exception_value, traceback
        self._enter_fault(LifecycleFaultCode.ACTOR_FAILURE)
        self._stop_preflight_actor()
        self._gate.release_owner()

    def _handle_start(self, command: StartCapture) -> LifecycleCommandResult:
        current = self._gate.snapshot()
        if current.state in {CaptureState.RECORDING, CaptureState.STARTING}:
            return self._result(True, False, "already_started")
        if current.state is CaptureState.PAUSED:
            return self._result(False, False, "capture_paused")
        if current.state is not CaptureState.OFF:
            return self._result(False, False, "invalid_start_state")

        try:
            configuration = self._configuration_source.snapshot()
        except Exception:
            return self._enter_fault(LifecycleFaultCode.PREFLIGHT_FAILURE)
        if not configuration.configuration.capture_permitted:
            return self._result(False, False, "capture_disabled_by_configuration")

        generation, transition = self._gate.begin_start(command.reason, configuration.revision)
        if not self._emit_transition(transition):
            return self._result(
                False,
                True,
                "audit_failure",
                LifecycleFaultCode.AUDIT_FAILURE,
            )

        preflight_ref = self._preflight_ref
        if preflight_ref is None or not preflight_ref.is_alive():
            return self._enter_fault(LifecycleFaultCode.PREFLIGHT_FAILURE)
        preflight_ref.tell(
            RunLifecyclePreflight(
                configuration=configuration,
                generation=generation,
                deadline_monotonic_ns=self._clock.monotonic_ns()
                + int(self._preflight_timeout_seconds * 1_000_000_000),
                reason=command.reason,
            )
        )
        return self._result(True, True, "starting")

    def _handle_preflight_complete(
        self, message: CompleteLifecyclePreflight
    ) -> LifecycleCommandResult:
        current = self._gate.snapshot()
        if current.state is not CaptureState.STARTING or current.generation != message.generation:
            return self._result(False, False, "stale_preflight_ignored")
        if not message.result.ready:
            fault_code = message.result.fault_code or LifecycleFaultCode.PREFLIGHT_FAILURE
            return self._enter_fault(fault_code)

        pause_reason = message.result.start_paused_reason or self._automatic_pause_reason
        if pause_reason is not None:
            generation, transition = self._gate.invalidate_and_pause(pause_reason)
            self._automatic_pause_reason = pause_reason
            if not self._emit_transition(transition):
                return self._result(
                    False,
                    True,
                    "audit_failure",
                    LifecycleFaultCode.AUDIT_FAILURE,
                )
            fault_code = self._drain_generation(generation)
            if fault_code is not None:
                return self._enter_fault(fault_code, drain_generation=False)
            return self._result(True, True, "session_safety_paused")

        transition = self._gate.mark_recording(message.generation, message.reason)
        if not self._emit_transition(transition):
            return self._result(
                False,
                True,
                "audit_failure",
                LifecycleFaultCode.AUDIT_FAILURE,
            )
        return self._result(True, True, "recording")

    def _handle_pause(self, command: PauseCapture) -> LifecycleCommandResult:
        current = self._gate.snapshot()
        if current.state is CaptureState.PAUSED:
            self._manual_pause = True
            return self._result(True, False, "already_paused")
        if current.state is not CaptureState.RECORDING:
            return self._result(False, False, "invalid_pause_state")
        self._manual_pause = True
        transition = self._gate.pause(command.reason)
        if not self._emit_transition(transition):
            return self._result(
                False,
                True,
                "audit_failure",
                LifecycleFaultCode.AUDIT_FAILURE,
            )
        return self._result(True, True, "paused")

    def _handle_resume(self, command: ResumeCapture) -> LifecycleCommandResult:
        current = self._gate.snapshot()
        if self._automatic_pause_reason is not None:
            return self._result(False, False, "session_safety_blocked")
        if current.state is CaptureState.RECORDING:
            self._manual_pause = False
            return self._result(True, False, "already_recording")
        if current.state is not CaptureState.PAUSED:
            return self._result(False, False, "invalid_resume_state")
        transition = self._gate.resume(command.reason)
        self._manual_pause = False
        if not self._emit_transition(transition):
            return self._result(
                False,
                True,
                "audit_failure",
                LifecycleFaultCode.AUDIT_FAILURE,
            )
        return self._result(True, True, "recording")

    def _handle_automatic_block(self, command: SetAutomaticCaptureBlock) -> LifecycleCommandResult:
        current = self._gate.snapshot()
        if command.blocked:
            if (
                self._automatic_pause_reason is TransitionReason.SESSION_LOCKED
                and command.reason is TransitionReason.IDLE
            ):
                return self._result(True, False, "stronger_safety_block_active")
            if (
                self._automatic_pause_reason is command.reason
                and current.state is CaptureState.PAUSED
            ):
                return self._result(True, False, "session_safety_already_blocked")

            self._automatic_pause_reason = command.reason
            if current.state in {CaptureState.OFF, CaptureState.STOPPING, CaptureState.FAULTED}:
                return self._result(True, False, "session_safety_latched")
            generation, transition = self._gate.invalidate_and_pause(command.reason)
            if not self._emit_transition(transition):
                return self._result(
                    False,
                    True,
                    "audit_failure",
                    LifecycleFaultCode.AUDIT_FAILURE,
                )
            fault_code = self._drain_generation(generation)
            if fault_code is not None:
                return self._enter_fault(fault_code, drain_generation=False)
            return self._result(True, True, "session_safety_paused")

        expected_release = (
            TransitionReason.SESSION_UNLOCKED
            if self._automatic_pause_reason is TransitionReason.SESSION_LOCKED
            else TransitionReason.ACTIVE
        )
        if self._automatic_pause_reason is None:
            return self._result(True, False, "session_safety_already_clear")
        if command.reason is not expected_release:
            return self._result(False, False, "session_safety_release_mismatch")

        self._automatic_pause_reason = None
        if current.state is not CaptureState.PAUSED or self._manual_pause:
            return self._result(True, False, "manual_pause_retained")
        transition = self._gate.resume(command.reason)
        if not self._emit_transition(transition):
            return self._result(
                False,
                True,
                "audit_failure",
                LifecycleFaultCode.AUDIT_FAILURE,
            )
        return self._result(True, True, "recording")

    def _handle_stop(self, command: StopCapture) -> LifecycleCommandResult:
        self._manual_pause = False
        current = self._gate.snapshot()
        if current.state is CaptureState.OFF:
            return self._result(True, False, "already_off")
        if current.state is CaptureState.FAULTED:
            fault_code = self._clear_buffers(None)
            if fault_code is not None:
                return self._result(False, False, "buffer_clear_failure", fault_code)
            transition = self._gate.finish_off(command.reason)
            if not self._emit_transition(transition):
                return self._result(
                    False,
                    True,
                    "audit_failure",
                    LifecycleFaultCode.AUDIT_FAILURE,
                )
            return self._result(True, True, "off")

        generation, transition = self._gate.begin_stopping(command.reason)
        if not self._emit_transition(transition):
            return self._result(
                False,
                True,
                "audit_failure",
                LifecycleFaultCode.AUDIT_FAILURE,
            )

        fault_code = self._drain_generation(generation)
        if fault_code is not None:
            return self._enter_fault(fault_code, drain_generation=False)

        transition = self._gate.finish_off(command.reason)
        if not self._emit_transition(transition):
            return self._result(
                False,
                True,
                "audit_failure",
                LifecycleFaultCode.AUDIT_FAILURE,
            )
        return self._result(True, True, "off")

    def _handle_fault(self, command: FaultCapture) -> LifecycleCommandResult:
        if self._gate.snapshot().state is CaptureState.FAULTED:
            return self._result(True, False, "already_faulted", command.fault_code)
        return self._enter_fault(command.fault_code, command.reason)

    def _enter_fault(
        self,
        fault_code: LifecycleFaultCode,
        reason: TransitionReason = TransitionReason.CRITICAL_FAULT,
        *,
        drain_generation: bool = True,
    ) -> LifecycleCommandResult:
        current = self._gate.snapshot()
        if current.state is CaptureState.FAULTED:
            return self._result(False, False, "faulted", fault_code)
        generation, transition = self._gate.fault(reason)
        self._emit_transition(transition, fault_code=fault_code, fail_closed=False)
        if drain_generation:
            self._drain_generation(generation)
        return self._result(False, True, "faulted", fault_code)

    def _drain_generation(self, generation: CaptureGeneration | None) -> LifecycleFaultCode | None:
        if generation is None:
            return self._clear_buffers(None)

        deadline = time.monotonic() + self._stop_timeout_seconds
        fault_code: LifecycleFaultCode | None = None
        try:
            self._work_coordinator.cancel_queued(generation)
        except Exception:
            fault_code = LifecycleFaultCode.CANCELLATION_FAILURE
        try:
            self._work_coordinator.cancel_in_flight(generation)
        except Exception:
            fault_code = fault_code or LifecycleFaultCode.CANCELLATION_FAILURE

        remaining = deadline - time.monotonic()
        gate_quiescent = remaining > 0 and self._gate.wait_for_operations(generation, remaining)
        remaining = deadline - time.monotonic()
        try:
            pipeline_quiescent = remaining > 0 and self._work_coordinator.wait_for_quiescence(
                generation, remaining
            )
        except Exception:
            pipeline_quiescent = False
        if not gate_quiescent or not pipeline_quiescent:
            fault_code = fault_code or LifecycleFaultCode.QUIESCENCE_TIMEOUT

        clear_failure = self._clear_buffers(generation)
        return fault_code or clear_failure

    def _clear_buffers(self, generation: CaptureGeneration | None) -> LifecycleFaultCode | None:
        try:
            self._work_coordinator.clear_volatile_buffers(generation)
        except Exception:
            return LifecycleFaultCode.BUFFER_CLEAR_FAILURE
        return None

    def _emit_transition(
        self,
        transition: CaptureStateTransition,
        *,
        fault_code: LifecycleFaultCode | None = None,
        fail_closed: bool = True,
    ) -> bool:
        event = LifecycleAuditEvent(
            previous=transition.previous,
            current=transition.current,
            reason=transition.reason,
            generation=transition.generation.value,
            configuration_revision=self._gate.configuration_revision_for_audit(),
            occurred_at=transition.occurred_at,
            fault_code=fault_code,
        )
        try:
            self._audit_sink.emit(event)
        except Exception:
            if fail_closed and self._gate.snapshot().state is not CaptureState.FAULTED:
                self._enter_fault(LifecycleFaultCode.AUDIT_FAILURE)
            return False
        return True

    def _stop_preflight_actor(self) -> None:
        preflight_ref = self._preflight_ref
        self._preflight_ref = None
        if preflight_ref is None or not preflight_ref.is_alive():
            return
        preflight_ref.stop(block=True, timeout=self._stop_timeout_seconds)

    def _result(
        self,
        accepted: bool,
        changed: bool,
        reason_code: str,
        fault_code: LifecycleFaultCode | None = None,
    ) -> LifecycleCommandResult:
        return LifecycleCommandResult(
            accepted=accepted,
            changed=changed,
            snapshot=self._gate.snapshot(),
            reason_code=reason_code,
            fault_code=fault_code,
        )
