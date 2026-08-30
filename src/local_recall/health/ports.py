"""Narrow diagnostic ports consumed by the health checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from local_recall.domain.lifecycle import CaptureStateSnapshot
from local_recall.ports.storage import StorageIntegrityReport


@dataclass(frozen=True, slots=True)
class CaptureBackendHealth:
    backend_id: str | None
    available: bool
    reason_code: str


@dataclass(frozen=True, slots=True)
class MetadataSourceHealth:
    source_id: str
    healthy: bool
    reason_code: str


@dataclass(frozen=True, slots=True)
class OcrHealth:
    available: bool
    reason_code: str


@dataclass(frozen=True, slots=True)
class RedactionHealth:
    functional: bool
    reason_code: str


@dataclass(frozen=True, slots=True)
class StorageHealth:
    available: bool
    reason_code: str
    record_count: int
    quarantined_records: int
    indexed_orphans: int


@dataclass(frozen=True, slots=True)
class IndexHealth:
    model_id: str | None
    dimensions: int
    record_count: int | None


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    provider_id: str
    available: bool


@dataclass(frozen=True, slots=True)
class DiskUsage:
    free_bytes: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class IpcHealth:
    responsive: bool
    reason_code: str


@runtime_checkable
class LifecycleStatePort(Protocol):
    def snapshot(self) -> CaptureStateSnapshot: ...


@runtime_checkable
class CaptureBackendHealthPort(Protocol):
    async def backend_health(self) -> CaptureBackendHealth: ...


@runtime_checkable
class MetadataSourcesHealthPort(Protocol):
    async def sources_health(self) -> tuple[MetadataSourceHealth, ...]: ...


@runtime_checkable
class OcrHealthPort(Protocol):
    async def ocr_health(self) -> OcrHealth: ...


@runtime_checkable
class RedactionHealthPort(Protocol):
    async def redaction_health(self) -> RedactionHealth: ...


@runtime_checkable
class StorageHealthPort(Protocol):
    async def storage_report(self) -> StorageHealth: ...


@runtime_checkable
class IndexHealthPort(Protocol):
    async def index_manifest(self) -> IndexHealth | None: ...


@runtime_checkable
class ProvidersHealthPort(Protocol):
    async def providers_report(self) -> tuple[ProviderHealth, ...]: ...


@runtime_checkable
class DiskUsagePort(Protocol):
    async def usage(self) -> DiskUsage: ...


@runtime_checkable
class IpcHealthPort(Protocol):
    async def ipc_report(self) -> IpcHealth: ...


@runtime_checkable
class IndexRepairPort(Protocol):
    async def rebuild_index(self) -> int: ...


@runtime_checkable
class StorageRepairPort(Protocol):
    async def cleanup_orphans(self) -> StorageIntegrityReport: ...


@runtime_checkable
class MigrationRepairPort(Protocol):
    async def resume_migrations(self) -> int: ...


@runtime_checkable
class ProviderReprobePort(Protocol):
    async def reprobe_providers(self) -> int: ...
