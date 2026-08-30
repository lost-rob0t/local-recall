from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pykka
import pytest

from local_recall.audit import AuditRecorder
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
from local_recall.health.bundle import build_diagnostic_bundle
from local_recall.health.guard import PrivacyDependencyFault, ensure_persistence_allowed
from local_recall.health.models import (
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
)
from local_recall.health.payload import health_report_diagnostic_payload
from local_recall.health.repair import RepairCommand, RepairRequest, SafeRepairService
from local_recall.health.service import HealthService
from local_recall.lifecycle import (
    CaptureGate,
    CaptureGateClosed,
    FaultCapture,
    LifecycleActor,
    LifecycleAuditEvent,
    LifecycleCommandResult,
    LifecycleFaultCode,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
    StaleCaptureGeneration,
    StopCapture,
)

_NOW = datetime(2026, 8, 30, tzinfo=UTC)
_SEEDED_MARKER = "synthetic-health-secret-marker-do-not-leak"


class _MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, event: object) -> None:
        self.events.append(event)


class HealthyLifecycleCheck:
    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.LIFECYCLE

    async def check(self) -> HealthCheckResult:
        return HealthCheckResult(
            check_id=HealthCheckId.LIFECYCLE, state=HealthState.HEALTHY, reason_code="ok"
        )


@pytest.fixture(autouse=True)
def stop_actors() -> Iterator[None]:
    yield
    pykka.ActorRegistry.stop_all(block=True, timeout=2)


class ExplodingRedactionCheck:
    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.REDACTION

    async def check(self) -> HealthCheckResult:
        raise RuntimeError(f"leak attempt {_SEEDED_MARKER}")


def _blocked_report() -> HealthReport:
    return HealthReport(
        results=(
            HealthCheckResult(
                check_id=HealthCheckId.REDACTION,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code="selftest-failed",
            ),
        )
    )


def _report_with_leaking_check() -> HealthReport:
    service = HealthService(
        checks=(HealthyLifecycleCheck(), ExplodingRedactionCheck()),
        per_check_timeout_seconds=1.0,
    )
    return asyncio.run(service.report())


def test_repair_failure_output_and_bundle_never_contain_seeded_content(tmp_path: Path) -> None:
    class ContentBearingIndexRepair:
        async def rebuild_index(self) -> int:
            raise RuntimeError(f"leak attempt {_SEEDED_MARKER}")

    sink = _MemoryAuditSink()
    service = SafeRepairService(
        index_repair=ContentBearingIndexRepair(),
        audit=AuditRecorder(sink),
        now=lambda: _NOW,
    )
    outcome = asyncio.run(
        service.run(
            RepairRequest(
                command=RepairCommand.INDEX_REBUILD,
                requested_at=_NOW,
                reason_code="operator-request",
            )
        )
    )
    assert outcome.reason_code == "repair-operation-failed"
    assert _SEEDED_MARKER not in repr(outcome)

    report = _report_with_leaking_check()
    bundle = build_diagnostic_bundle(
        report,
        now=lambda: _NOW,
        record_count=1,
        storage_bytes=2,
        revisions=("policy-v4",),
    )
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(bundle.to_json(), encoding="utf-8")
    assert _SEEDED_MARKER not in bundle_path.read_text(encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "detect_secrets", "scan", str(bundle_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0
    document = cast("dict[str, object]", json.loads(result.stdout))
    assert document.get("results", {}) == {}


def test_health_failures_are_content_free_across_surfaces() -> None:
    report = _report_with_leaking_check()
    payload = health_report_diagnostic_payload(report)
    surfaces = (
        repr(report),
        report.to_json(),
        repr(payload),
        payload.to_json(),
        repr(
            build_diagnostic_bundle(
                report, now=lambda: _NOW, record_count=0, storage_bytes=0, revisions=()
            )
        ),
    )
    for surface in surfaces:
        assert _SEEDED_MARKER not in surface


def test_repair_commands_never_delete_records_or_touch_policy() -> None:
    command_values = {item.value for item in RepairCommand}
    assert "delete-records" not in command_values
    assert "purge" not in command_values
    assert all("privacy" not in value and "policy" not in value for value in command_values)


def test_failing_redaction_prevents_persistence() -> None:
    persisted: list[str] = []

    def persist_after_health_gate(record: str) -> None:
        ensure_persistence_allowed(_blocked_report())
        persisted.append(record)

    with pytest.raises(PrivacyDependencyFault):
        persist_after_health_gate("synthetic-record")
    assert persisted == []


class Source:
    def snapshot(self) -> ConfigurationSnapshot:
        return ConfigurationSnapshot(
            configuration=_active_configuration(),
            revision="config-on",
            source="synthetic",
            loaded_at=datetime.now(UTC),
        )


def _active_configuration() -> LocalRecallConfig:
    return LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_ONLY,
        capture=CaptureSettings(enabled=True),
        metadata=MetadataSettings(enabled_sources=("synthetic",)),
        encryption=EncryptionSettings(
            provider_id="synthetic-encryption",
            key_reference=CredentialReference(
                provider_id="synthetic-key-provider",
                reference="health-architecture-test-key",
            ),
        ),
        storage=StorageSettings(
            backend_id="synthetic-storage",
            root_directory="/tmp/local-recall-health-architecture-tests",
        ),
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

    def wait_for_quiescence(
        self,
        generation: CaptureGeneration,
        *,
        timeout_seconds: float,
    ) -> bool:
        del generation, timeout_seconds
        return True

    def clear_volatile_buffers(self, generation: CaptureGeneration | None) -> None:
        del generation


class Audit:
    def emit(self, event: LifecycleAuditEvent) -> None:
        del event


def test_capture_faults_when_critical_privacy_dependency_fails() -> None:
    gate = CaptureGate()
    actor_ref = LifecycleActor.start(
        gate=gate,
        configuration_source=Source(),
        preflight=Preflight(),
        work_coordinator=Coordinator(),
        audit_sink=Audit(),
        stop_timeout_seconds=1,
    )
    deadline = time.monotonic() + 2
    state = gate.snapshot()
    while state.state is not CaptureState.RECORDING and time.monotonic() < deadline:
        threading.Event().wait(0.005)
        state = gate.snapshot()
    assert state.state is CaptureState.RECORDING
    generation = state.generation
    assert generation is not None

    ensure_persistence_allowed(HealthReport(results=()))
    with pytest.raises(PrivacyDependencyFault):
        ensure_persistence_allowed(_blocked_report())

    result = cast(
        LifecycleCommandResult,
        actor_ref.ask(FaultCapture(fault_code=LifecycleFaultCode.PREFLIGHT_FAILURE), timeout=2),
    )
    assert result.snapshot.state is CaptureState.FAULTED
    assert result.snapshot.critical_dependencies_healthy is False

    with pytest.raises((CaptureGateClosed, StaleCaptureGeneration)):
        gate.run_capture(lambda permit: permit)

    cast(LifecycleCommandResult, actor_ref.ask(StopCapture(), timeout=2))
