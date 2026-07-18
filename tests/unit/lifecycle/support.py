from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

import pykka

from local_recall.config import (
    CaptureSettings,
    ConfigurationSnapshot,
    CredentialReference,
    EncryptionSettings,
    LocalRecallConfig,
    MetadataSettings,
    PrivacyProfile,
    StorageSettings,
)
from local_recall.domain.lifecycle import CaptureGeneration, CaptureState, CaptureStateSnapshot
from local_recall.lifecycle import (
    CaptureGate,
    GetLifecycleSnapshot,
    LifecycleActor,
    LifecycleAuditEvent,
    LifecycleCommandResult,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
)


def lifecycle_configuration(enabled: bool) -> LocalRecallConfig:
    if not enabled:
        return LocalRecallConfig.safe_default()
    return LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_ONLY,
        capture=CaptureSettings(enabled=True),
        metadata=MetadataSettings(enabled_sources=("synthetic",)),
        encryption=EncryptionSettings(
            provider_id="synthetic-encryption",
            key_reference=CredentialReference(
                provider_id="synthetic-key-provider",
                reference="lifecycle-test-key",
            ),
        ),
        storage=StorageSettings(
            backend_id="synthetic-storage",
            root_directory="/tmp/local-recall-lifecycle-tests",
        ),
    )


class MutableConfigurationSource:
    def __init__(self, enabled: bool) -> None:
        self.set_enabled(enabled)

    def set_enabled(self, enabled: bool) -> None:
        self._snapshot = ConfigurationSnapshot(
            configuration=lifecycle_configuration(enabled),
            revision=f"config-{'on' if enabled else 'off'}",
            source="synthetic",
            loaded_at=datetime.now(UTC),
        )

    def snapshot(self) -> ConfigurationSnapshot:
        return self._snapshot


@dataclass
class SyntheticPreflight:
    result: LifecyclePreflightResult = field(default_factory=LifecyclePreflightResult.success)
    requests: list[LifecyclePreflightRequest] | None = None

    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        if self.requests is not None:
            self.requests.append(request)
        return self.result


class SyntheticWorkCoordinator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int | None]] = []
        self.quiescent = True
        self.raise_cancel = False
        self.raise_in_flight = False
        self.raise_clear = False
        self.on_cancel: Callable[[CaptureGeneration], None] | None = None

    def cancel_queued(self, generation: CaptureGeneration) -> None:
        self.calls.append(("cancel_queued", generation.value))
        if self.on_cancel is not None:
            self.on_cancel(generation)
        if self.raise_cancel:
            raise RuntimeError("synthetic cancel failure")

    def cancel_in_flight(self, generation: CaptureGeneration) -> None:
        self.calls.append(("cancel_in_flight", generation.value))
        if self.raise_in_flight:
            raise RuntimeError("synthetic in-flight cancellation failure")

    def wait_for_quiescence(self, generation: CaptureGeneration, timeout_seconds: float) -> bool:
        del timeout_seconds
        self.calls.append(("wait_for_quiescence", generation.value))
        return self.quiescent

    def clear_volatile_buffers(self, generation: CaptureGeneration | None) -> None:
        self.calls.append(
            ("clear_volatile_buffers", None if generation is None else generation.value)
        )
        if self.raise_clear:
            raise RuntimeError("synthetic clear failure")


class SyntheticAuditSink:
    def __init__(self) -> None:
        self.events: list[LifecycleAuditEvent] = []
        self.raise_on_emit = False
        self.fail_after: int | None = None

    def emit(self, event: LifecycleAuditEvent) -> None:
        if self.raise_on_emit or (
            self.fail_after is not None and len(self.events) >= self.fail_after
        ):
            raise RuntimeError("synthetic audit failure")
        self.events.append(event)


class BlockingPreflight:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        del request
        self.entered.set()
        assert self.release.wait(1)
        return LifecyclePreflightResult.success()


class BlockingCoordinator(SyntheticWorkCoordinator):
    def __init__(self) -> None:
        super().__init__()
        self.wait_entered = threading.Event()
        self.wait_release = threading.Event()

    def wait_for_quiescence(self, generation: CaptureGeneration, timeout_seconds: float) -> bool:
        del timeout_seconds
        self.calls.append(("wait_for_quiescence", generation.value))
        self.wait_entered.set()
        return self.wait_release.wait(1)


class CancellationAwarePreflight:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.cancelled = threading.Event()

    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        self.entered.set()
        if request.cancellation.wait_cancelled(1):
            self.cancelled.set()
        return LifecyclePreflightResult.success()


class UncooperativePreflight:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        del request
        self.entered.set()
        assert self.release.wait(1)
        return LifecyclePreflightResult.success()


def start_actor(
    *,
    enabled: bool = False,
    preflight: SyntheticPreflight
    | BlockingPreflight
    | CancellationAwarePreflight
    | UncooperativePreflight
    | None = None,
    coordinator: SyntheticWorkCoordinator | None = None,
    audit: SyntheticAuditSink | None = None,
    gate: CaptureGate | None = None,
    source: MutableConfigurationSource | None = None,
) -> tuple[
    pykka.ActorRef[LifecycleActor],
    CaptureGate,
    MutableConfigurationSource,
    SyntheticWorkCoordinator,
    SyntheticAuditSink,
]:
    actual_gate = gate or CaptureGate()
    actual_source = source or MutableConfigurationSource(enabled)
    actual_coordinator = coordinator or SyntheticWorkCoordinator()
    actual_audit = audit or SyntheticAuditSink()
    actor_ref = LifecycleActor.start(
        gate=actual_gate,
        configuration_source=actual_source,
        preflight=preflight or SyntheticPreflight(),
        work_coordinator=actual_coordinator,
        audit_sink=actual_audit,
        preflight_timeout_seconds=1,
        stop_timeout_seconds=1,
    )
    ask_snapshot(actor_ref)
    if enabled:
        wait_for_state(actor_ref, {CaptureState.RECORDING, CaptureState.FAULTED})
    return actor_ref, actual_gate, actual_source, actual_coordinator, actual_audit


def ask_snapshot(actor_ref: pykka.ActorRef[LifecycleActor]) -> CaptureStateSnapshot:
    return cast(CaptureStateSnapshot, actor_ref.ask(GetLifecycleSnapshot(), timeout=2))


def ask_result(
    actor_ref: pykka.ActorRef[LifecycleActor], message: object
) -> LifecycleCommandResult:
    return cast(LifecycleCommandResult, actor_ref.ask(message, timeout=2))


def snapshot(actor_ref: pykka.ActorRef[LifecycleActor]) -> CaptureStateSnapshot:
    return ask_snapshot(actor_ref)


def wait_for_state(
    actor_ref: pykka.ActorRef[LifecycleActor],
    expected: CaptureState | set[CaptureState],
    timeout: float = 1.0,
) -> CaptureStateSnapshot:
    expected_states = {expected} if isinstance(expected, CaptureState) else expected
    deadline = time.monotonic() + timeout
    current = snapshot(actor_ref)
    while current.state not in expected_states and time.monotonic() < deadline:
        threading.Event().wait(0.005)
        current = snapshot(actor_ref)
    assert current.state in expected_states
    return current
