from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import cast

import pykka
import pytest

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
from local_recall.domain.lifecycle import CaptureGeneration, CaptureState
from local_recall.lifecycle import (
    CaptureGate,
    CaptureGateClosed,
    LifecycleActor,
    LifecycleAuditEvent,
    LifecycleCommandResult,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
    StaleCaptureGeneration,
    StopCapture,
)


@pytest.fixture(autouse=True)
def stop_actors() -> Iterator[None]:
    yield
    pykka.ActorRegistry.stop_all(block=True, timeout=2)


def active_configuration() -> LocalRecallConfig:
    return LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_ONLY,
        capture=CaptureSettings(enabled=True),
        metadata=MetadataSettings(enabled_sources=("synthetic",)),
        encryption=EncryptionSettings(
            provider_id="synthetic-encryption",
            key_reference=CredentialReference(
                provider_id="synthetic-key-provider",
                reference="hard-gate-test-key",
            ),
        ),
        storage=StorageSettings(
            backend_id="synthetic-storage",
            root_directory="/tmp/local-recall-hard-gate-tests",
        ),
    )


class Source:
    def snapshot(self) -> ConfigurationSnapshot:
        return ConfigurationSnapshot(
            configuration=active_configuration(),
            revision="config-on",
            source="synthetic",
            loaded_at=datetime.now(UTC),
        )


class Preflight:
    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        del request
        return LifecyclePreflightResult.success()


class Coordinator:
    def cancel_queued(self, generation: CaptureGeneration) -> None:
        del generation

    def cancel_in_flight(self, generation: CaptureGeneration) -> None:
        del generation

    def wait_for_quiescence(self, generation: CaptureGeneration, timeout_seconds: float) -> bool:
        del generation, timeout_seconds
        return True

    def clear_volatile_buffers(self, generation: CaptureGeneration | None) -> None:
        del generation


class Audit:
    def emit(self, event: LifecycleAuditEvent) -> None:
        del event


def test_off_gate_never_invokes_capture_backend() -> None:
    gate = CaptureGate()
    called = False

    def backend(_: object) -> None:
        nonlocal called
        called = True

    with pytest.raises(CaptureGateClosed):
        gate.run_capture(backend)

    assert not called


def test_off_gate_never_invokes_persistence_commit() -> None:
    gate = CaptureGate()
    called = False

    def commit(_: object) -> None:
        nonlocal called
        called = True

    with pytest.raises(CaptureGateClosed):
        gate.run_persistence(CaptureGeneration(1), commit)

    assert not called


def test_stopped_generation_cannot_commit() -> None:
    gate = CaptureGate()
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=Source(),
        preflight=Preflight(),
        work_coordinator=Coordinator(),
        audit_sink=Audit(),
        stop_timeout_seconds=1,
    )
    deadline = time.monotonic() + 1
    state = gate.snapshot()
    while state.state is not CaptureState.RECORDING and time.monotonic() < deadline:
        threading.Event().wait(0.005)
        state = gate.snapshot()
    assert state.state is CaptureState.RECORDING
    generation = state.generation
    assert generation is not None

    result = cast(LifecycleCommandResult, actor_ref.ask(StopCapture(), timeout=2))
    assert result.snapshot.state is CaptureState.OFF

    with pytest.raises((CaptureGateClosed, StaleCaptureGeneration)):
        gate.run_persistence(generation, lambda permit: permit)


def test_actor_registry_is_clean_after_shutdown() -> None:
    gate = CaptureGate()
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=Source(),
        preflight=Preflight(),
        work_coordinator=Coordinator(),
        audit_sink=Audit(),
    )

    assert actor_ref in pykka.ActorRegistry.get_all()
    assert actor_ref.stop(block=True, timeout=2)
    assert actor_ref not in pykka.ActorRegistry.get_all()
