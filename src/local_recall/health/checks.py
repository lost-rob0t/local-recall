"""Concrete health checks over the narrow diagnostic ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from local_recall.domain.crypto import KeyPurpose, KeyRequest
from local_recall.domain.lifecycle import CaptureState
from local_recall.health.models import (
    HealthCheckId,
    HealthCheckResult,
    HealthState,
    criticality_for,
)
from local_recall.health.ports import (
    CaptureBackendHealthPort,
    DiskUsage,
    DiskUsagePort,
    IndexHealthPort,
    IpcHealthPort,
    LifecycleStatePort,
    MetadataSourcesHealthPort,
    OcrHealthPort,
    ProvidersHealthPort,
    RedactionHealthPort,
    StorageHealthPort,
)
from local_recall.ports.keys import KeyHealthReport, KeyHealthStatus


@runtime_checkable
class KeyHealthPort(Protocol):
    async def health(self, request: KeyRequest) -> KeyHealthReport: ...


@runtime_checkable
class HealthCheck(Protocol):
    @property
    def check_id(self) -> HealthCheckId: ...

    async def check(self) -> HealthCheckResult: ...


_KEY_REASON_CODES = {
    KeyHealthStatus.READY: "key-ready",
    KeyHealthStatus.LOCKED: "key-locked",
    KeyHealthStatus.UNAVAILABLE: "key-unavailable",
    KeyHealthStatus.INVALID: "key-invalid",
    KeyHealthStatus.REVOKED: "key-revoked",
}


class LifecycleHealthCheck:
    def __init__(self, port: LifecycleStatePort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.LIFECYCLE

    async def check(self) -> HealthCheckResult:
        snapshot = self._port.snapshot()
        if snapshot.critical_dependencies_healthy:
            state = HealthState.HEALTHY
            reason = "lifecycle-dependencies-healthy"
        elif snapshot.state is CaptureState.FAULTED:
            state = HealthState.CAPTURE_BLOCKING
            reason = "lifecycle-faulted"
        else:
            state = HealthState.DEGRADED
            reason = "lifecycle-dependencies-unhealthy"
        return HealthCheckResult(check_id=self.check_id, state=state, reason_code=reason)


class CaptureBackendHealthCheck:
    def __init__(self, port: CaptureBackendHealthPort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.CAPTURE_BACKEND

    async def check(self) -> HealthCheckResult:
        report = await self._port.backend_health()
        if report.available:
            return HealthCheckResult(
                check_id=self.check_id, state=HealthState.HEALTHY, reason_code=report.reason_code
            )
        return HealthCheckResult(
            check_id=self.check_id,
            state=HealthState.CAPTURE_BLOCKING,
            reason_code=report.reason_code,
        )


class MetadataSourcesHealthCheck:
    def __init__(self, port: MetadataSourcesHealthPort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.METADATA_SOURCES

    async def check(self) -> HealthCheckResult:
        sources = await self._port.sources_health()
        if not sources:
            return HealthCheckResult(
                check_id=self.check_id,
                state=HealthState.HEALTHY,
                reason_code="no-sources-configured",
            )
        unhealthy = [item for item in sources if not item.healthy]
        if not unhealthy:
            return HealthCheckResult(
                check_id=self.check_id, state=HealthState.HEALTHY, reason_code="sources-healthy"
            )
        return HealthCheckResult(
            check_id=self.check_id,
            state=HealthState.DEGRADED,
            reason_code=unhealthy[0].reason_code,
        )


class OcrHealthCheck:
    def __init__(self, port: OcrHealthPort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.OCR

    async def check(self) -> HealthCheckResult:
        report = await self._port.ocr_health()
        state = HealthState.HEALTHY if report.available else HealthState.DEGRADED
        return HealthCheckResult(
            check_id=self.check_id, state=state, reason_code=report.reason_code
        )


class RedactionHealthCheck:
    def __init__(self, port: RedactionHealthPort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.REDACTION

    async def check(self) -> HealthCheckResult:
        report = await self._port.redaction_health()
        if report.functional:
            return HealthCheckResult(
                check_id=self.check_id, state=HealthState.HEALTHY, reason_code=report.reason_code
            )
        return HealthCheckResult(
            check_id=self.check_id,
            state=HealthState.CAPTURE_BLOCKING,
            reason_code=report.reason_code,
        )


class EncryptionKeysHealthCheck:
    def __init__(self, provider: KeyHealthPort) -> None:
        self._provider = provider

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.ENCRYPTION_KEYS

    async def check(self) -> HealthCheckResult:
        report = await self._provider.health(KeyRequest(purpose=KeyPurpose.RECORD))
        status = report.status
        reason = _KEY_REASON_CODES.get(status, "key-unavailable")
        state = (
            HealthState.HEALTHY if status is KeyHealthStatus.READY else HealthState.CAPTURE_BLOCKING
        )
        return HealthCheckResult(check_id=self.check_id, state=state, reason_code=reason)


class StorageIntegrityHealthCheck:
    def __init__(self, port: StorageHealthPort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.STORAGE_INTEGRITY

    async def check(self) -> HealthCheckResult:
        report = await self._port.storage_report()
        if not report.available:
            return HealthCheckResult(
                check_id=self.check_id,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code=report.reason_code,
            )
        if report.quarantined_records > 0:
            return HealthCheckResult(
                check_id=self.check_id,
                state=HealthState.DEGRADED,
                reason_code="quarantined-records-present",
            )
        return HealthCheckResult(
            check_id=self.check_id, state=HealthState.HEALTHY, reason_code=report.reason_code
        )


class IndexHealthCheck:
    def __init__(self, index_port: IndexHealthPort, storage_port: StorageHealthPort) -> None:
        self._index_port = index_port
        self._storage_port = storage_port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.INDEXES

    async def check(self) -> HealthCheckResult:
        manifest = await self._index_port.index_manifest()
        if manifest is None or manifest.model_id is None or manifest.record_count is None:
            return HealthCheckResult(
                check_id=self.check_id, state=HealthState.DEGRADED, reason_code="index-unavailable"
            )
        storage = await self._storage_port.storage_report()
        if manifest.record_count != storage.record_count:
            return HealthCheckResult(
                check_id=self.check_id,
                state=HealthState.DEGRADED,
                reason_code="index-behind-storage",
            )
        return HealthCheckResult(
            check_id=self.check_id, state=HealthState.HEALTHY, reason_code="index-current"
        )


class ModelProvidersHealthCheck:
    def __init__(self, port: ProvidersHealthPort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.MODEL_PROVIDERS

    async def check(self) -> HealthCheckResult:
        providers = await self._port.providers_report()
        unavailable = [item for item in providers if not item.available]
        if not unavailable:
            return HealthCheckResult(
                check_id=self.check_id,
                state=HealthState.HEALTHY,
                reason_code="providers-available",
            )
        return HealthCheckResult(
            check_id=self.check_id,
            state=HealthState.DEGRADED,
            reason_code="provider-unavailable",
        )


class DiskQuotaHealthCheck:
    def __init__(self, port: DiskUsagePort, *, min_free_bytes: int) -> None:
        if min_free_bytes <= 0:
            raise ValueError("minimum free bytes must be positive")
        self._port = port
        self._min_free_bytes = min_free_bytes

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.DISK_QUOTA

    async def check(self) -> HealthCheckResult:
        usage = await self._port.usage()
        _validate_usage(usage)
        if usage.free_bytes < self._min_free_bytes:
            return HealthCheckResult(
                check_id=self.check_id,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code="disk-quota-exhausted",
            )
        return HealthCheckResult(
            check_id=self.check_id, state=HealthState.HEALTHY, reason_code="disk-quota-ok"
        )


class DaemonIpcHealthCheck:
    def __init__(self, port: IpcHealthPort) -> None:
        self._port = port

    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.DAEMON_IPC

    async def check(self) -> HealthCheckResult:
        report = await self._port.ipc_report()
        state = HealthState.HEALTHY if report.responsive else HealthState.DEGRADED
        return HealthCheckResult(
            check_id=self.check_id, state=state, reason_code=report.reason_code
        )


@dataclass(frozen=True, slots=True)
class _CheckPorts:
    lifecycle_state_port: LifecycleStatePort
    capture_backend_port: CaptureBackendHealthPort
    metadata_sources_port: MetadataSourcesHealthPort
    ocr_port: OcrHealthPort
    redaction_port: RedactionHealthPort
    key_provider: KeyHealthPort
    storage_port: StorageHealthPort
    index_port: IndexHealthPort
    providers_port: ProvidersHealthPort
    disk_port: DiskUsagePort
    ipc_port: IpcHealthPort
    min_free_bytes: int


def build_health_checks(
    *,
    lifecycle_state_port: LifecycleStatePort,
    capture_backend_port: CaptureBackendHealthPort,
    metadata_sources_port: MetadataSourcesHealthPort,
    ocr_port: OcrHealthPort,
    redaction_port: RedactionHealthPort,
    key_provider: KeyHealthPort,
    storage_port: StorageHealthPort,
    index_port: IndexHealthPort,
    providers_port: ProvidersHealthPort,
    disk_port: DiskUsagePort,
    ipc_port: IpcHealthPort,
    min_free_bytes: int,
) -> tuple[HealthCheck, ...]:
    ports = _CheckPorts(
        lifecycle_state_port=lifecycle_state_port,
        capture_backend_port=capture_backend_port,
        metadata_sources_port=metadata_sources_port,
        ocr_port=ocr_port,
        redaction_port=redaction_port,
        key_provider=key_provider,
        storage_port=storage_port,
        index_port=index_port,
        providers_port=providers_port,
        disk_port=disk_port,
        ipc_port=ipc_port,
        min_free_bytes=min_free_bytes,
    )
    return (
        LifecycleHealthCheck(ports.lifecycle_state_port),
        CaptureBackendHealthCheck(ports.capture_backend_port),
        MetadataSourcesHealthCheck(ports.metadata_sources_port),
        OcrHealthCheck(ports.ocr_port),
        RedactionHealthCheck(ports.redaction_port),
        EncryptionKeysHealthCheck(ports.key_provider),
        StorageIntegrityHealthCheck(ports.storage_port),
        IndexHealthCheck(ports.index_port, ports.storage_port),
        ModelProvidersHealthCheck(ports.providers_port),
        DiskQuotaHealthCheck(ports.disk_port, min_free_bytes=ports.min_free_bytes),
        DaemonIpcHealthCheck(ports.ipc_port),
    )


def _validate_usage(usage: DiskUsage) -> None:
    if usage.free_bytes < 0 or usage.total_bytes <= 0 or usage.free_bytes > usage.total_bytes:
        raise ValueError("disk usage report is invalid")


__all__ = [
    "HealthCheck",
    "build_health_checks",
    "criticality_for",
]
