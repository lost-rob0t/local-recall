from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime

from local_recall.domain.crypto import KeyHandle, KeyRequest
from local_recall.domain.lifecycle import CaptureGeneration, CaptureState, CaptureStateSnapshot
from local_recall.health.checks import HealthCheck, build_health_checks
from local_recall.health.models import HealthCheckId, HealthCheckResult, HealthState
from local_recall.health.ports import (
    CaptureBackendHealth,
    DiskUsage,
    IndexHealth,
    IpcHealth,
    MetadataSourceHealth,
    OcrHealth,
    ProviderHealth,
    RedactionHealth,
    StorageHealth,
)
from local_recall.ports.keys import KeyHealthReport, KeyHealthStatus

_NOW = datetime(2026, 8, 30, tzinfo=UTC)


class FakeKeyProvider:
    def __init__(self, status: KeyHealthStatus) -> None:
        self._status = status

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        del request
        return KeyHealthReport(
            provider_id="memory-keyring",
            status=self._status,
            key=KeyHandle(key_id="k1", provider_id="memory-keyring", version=1),
        )


@dataclass
class FakePorts:
    lifecycle: CaptureStateSnapshot = field(
        default_factory=lambda: CaptureStateSnapshot(
            state=CaptureState.RECORDING,
            generation=CaptureGeneration(1),
            observed_at=_NOW,
            privacy_mode=False,
            critical_dependencies_healthy=True,
        )
    )
    backend: CaptureBackendHealth = field(
        default_factory=lambda: CaptureBackendHealth(
            backend_id="xorg", available=True, reason_code="available"
        )
    )
    sources: tuple[MetadataSourceHealth, ...] = field(
        default_factory=tuple[MetadataSourceHealth, ...]
    )
    ocr: OcrHealth = field(default_factory=lambda: OcrHealth(available=True, reason_code="ready"))
    redaction: RedactionHealth = field(
        default_factory=lambda: RedactionHealth(functional=True, reason_code="functional")
    )
    key_status: KeyHealthStatus = KeyHealthStatus.READY
    storage: StorageHealth = field(
        default_factory=lambda: StorageHealth(
            available=True,
            reason_code="available",
            record_count=3,
            quarantined_records=0,
            indexed_orphans=0,
        )
    )
    index: IndexHealth | None = field(
        default_factory=lambda: IndexHealth(model_id="text-model-v1", dimensions=8, record_count=3)
    )
    providers: tuple[ProviderHealth, ...] = field(
        default_factory=lambda: (ProviderHealth(provider_id="ollama-local", available=True),)
    )
    disk: DiskUsage = field(
        default_factory=lambda: DiskUsage(free_bytes=10_000_000_000, total_bytes=50_000_000_000)
    )
    ipc: IpcHealth = field(default_factory=lambda: IpcHealth(responsive=True, reason_code="ready"))

    def snapshot(self) -> CaptureStateSnapshot:
        return self.lifecycle

    async def backend_health(self) -> CaptureBackendHealth:
        return self.backend

    async def sources_health(self) -> tuple[MetadataSourceHealth, ...]:
        return self.sources

    async def ocr_health(self) -> OcrHealth:
        return self.ocr

    async def redaction_health(self) -> RedactionHealth:
        return self.redaction

    async def storage_report(self) -> StorageHealth:
        return self.storage

    async def index_manifest(self) -> IndexHealth | None:
        return self.index

    async def providers_report(self) -> tuple[ProviderHealth, ...]:
        return self.providers

    async def usage(self) -> DiskUsage:
        return self.disk

    async def ipc_report(self) -> IpcHealth:
        return self.ipc


def build(ports: FakePorts, *, min_free_bytes: int = 1_000_000) -> tuple[HealthCheck, ...]:
    return build_health_checks(
        lifecycle_state_port=ports,
        capture_backend_port=ports,
        metadata_sources_port=ports,
        ocr_port=ports,
        redaction_port=ports,
        key_provider=FakeKeyProvider(ports.key_status),
        storage_port=ports,
        index_port=ports,
        providers_port=ports,
        disk_port=ports,
        ipc_port=ports,
        min_free_bytes=min_free_bytes,
    )


def _result(check: object) -> HealthCheckResult:
    return asyncio.run(check.check())  # type: ignore[attr-defined]


def test_all_eleven_checks_are_registered() -> None:
    checks = build(FakePorts())
    assert sorted(check.check_id.value for check in checks) == sorted(
        item.value for item in HealthCheckId
    )


def test_all_healthy_ports_produce_healthy_checks() -> None:
    checks = build(FakePorts())
    for check in checks:
        assert _result(check).state is HealthState.HEALTHY


def test_backend_unavailable_is_capture_blocking() -> None:
    ports = FakePorts()
    ports.backend = CaptureBackendHealth(
        backend_id=None, available=False, reason_code="unavailable"
    )
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.CAPTURE_BACKEND).check()
    )
    assert result.state is HealthState.CAPTURE_BLOCKING
    assert result.reason_code == "unavailable"


def test_metadata_source_failure_is_degraded_not_blocking() -> None:
    ports = FakePorts()
    ports.sources = (MetadataSourceHealth(source_id="qtile", healthy=False, reason_code="failed"),)
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.METADATA_SOURCES).check()
    )
    assert result.state is HealthState.DEGRADED
    assert result.reason_code == "failed"


def test_key_locked_is_capture_blocking() -> None:
    ports = FakePorts()
    ports.key_status = KeyHealthStatus.LOCKED
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.ENCRYPTION_KEYS).check()
    )
    assert result.state is HealthState.CAPTURE_BLOCKING
    assert result.reason_code == "key-locked"


def test_redaction_selftest_failure_is_capture_blocking() -> None:
    ports = FakePorts()
    ports.redaction = RedactionHealth(functional=False, reason_code="selftest-failed")
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.REDACTION).check()
    )
    assert result.state is HealthState.CAPTURE_BLOCKING
    assert result.reason_code == "selftest-failed"


def test_low_disk_is_capture_blocking() -> None:
    ports = FakePorts()
    ports.disk = DiskUsage(free_bytes=500, total_bytes=50_000_000_000)
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.DISK_QUOTA).check()
    )
    assert result.state is HealthState.CAPTURE_BLOCKING
    assert result.reason_code == "disk-quota-exhausted"


def test_index_divergence_is_degraded() -> None:
    ports = FakePorts()
    ports.index = IndexHealth(model_id="text-model-v1", dimensions=8, record_count=1)
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.INDEXES).check()
    )
    assert result.state is HealthState.DEGRADED
    assert result.reason_code == "index-behind-storage"


def test_missing_index_manifest_is_degraded() -> None:
    ports = FakePorts()
    ports.index = None
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.INDEXES).check()
    )
    assert result.state is HealthState.DEGRADED
    assert result.reason_code == "index-unavailable"


def test_quarantined_storage_records_are_degraded() -> None:
    ports = FakePorts()
    ports.storage = StorageHealth(
        available=True,
        reason_code="available",
        record_count=2,
        quarantined_records=1,
        indexed_orphans=0,
    )
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.STORAGE_INTEGRITY).check()
    )
    assert result.state is HealthState.DEGRADED
    assert result.reason_code == "quarantined-records-present"


def test_unresponsive_ipc_is_degraded() -> None:
    ports = FakePorts()
    ports.ipc = IpcHealth(responsive=False, reason_code="unresponsive")
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.DAEMON_IPC).check()
    )
    assert result.state is HealthState.DEGRADED


def test_unavailable_provider_is_degraded() -> None:
    ports = FakePorts()
    ports.providers = (ProviderHealth(provider_id="ollama-local", available=False),)
    result = asyncio.run(
        next(c for c in build(ports) if c.check_id is HealthCheckId.MODEL_PROVIDERS).check()
    )
    assert result.state is HealthState.DEGRADED
