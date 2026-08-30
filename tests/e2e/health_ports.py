"""Health ports bound to the live E2E system for realistic health reports."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from local_recall.domain.crypto import KeyPurpose, KeyRequest
from local_recall.domain.frames import OCRBlock, OCRResult, PixelFormat, RawFrame
from local_recall.domain.lifecycle import CaptureGeneration, CaptureStateSnapshot
from local_recall.domain.metadata import SourceConfidence
from local_recall.domain.redaction import PixelRegion
from local_recall.health.checks import HealthCheck, build_health_checks
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
from local_recall.ports.redaction import RedactionRequest

from .harness import POLICY_REVISION, LocalRecallSystem


@dataclass
class SystemHealthPorts:
    system: LocalRecallSystem
    free_bytes: int = 10_000_000_000

    def snapshot(self) -> CaptureStateSnapshot:
        return self.system.gate.snapshot()

    async def backend_health(self) -> CaptureBackendHealth:
        return CaptureBackendHealth(
            backend_id=self.system.capture_backend.backend_id,
            available=True,
            reason_code="available",
        )

    async def sources_health(self) -> tuple[MetadataSourceHealth, ...]:
        return (
            MetadataSourceHealth(
                source_id="synthetic-desktop", healthy=True, reason_code="healthy"
            ),
        )

    async def ocr_health(self) -> OcrHealth:
        return OcrHealth(available=True, reason_code="available")

    async def redaction_health(self) -> RedactionHealth:
        observed_at = self.system.clock.now()
        generation = self.system.gate.snapshot().generation or CaptureGeneration(1)
        frame = RawFrame(
            frame_id=uuid4(),
            generation=generation,
            captured_at=observed_at,
            width=8,
            height=1,
            stride=24,
            pixel_format=PixelFormat.RGB8,
            pixels=bytes(24),
            metadata=self.system.desktop.metadata(observed_at),
        )
        ocr = OCRResult(
            frame.frame_id,
            (
                OCRBlock(
                    block_id=uuid4(),
                    frame_id=frame.frame_id,
                    text="benign selftest line",
                    confidence=SourceConfidence(0.99),
                    region=PixelRegion(0, 0, 8, 1),
                ),
            ),
        )
        try:
            record = await self.system.policy.redact(
                RedactionRequest(frame=frame, ocr=ocr, policy_revision=POLICY_REVISION)
            )
        except Exception:
            return RedactionHealth(functional=False, reason_code="selftest-failed")
        if record.frame.ocr_text:
            return RedactionHealth(functional=True, reason_code="functional")
        return RedactionHealth(functional=False, reason_code="selftest-failed")

    async def storage_report(self) -> StorageHealth:
        usage = await self.system.storage.usage()
        return StorageHealth(
            available=True,
            reason_code="available",
            record_count=usage.ready_records,
            quarantined_records=0,
            indexed_orphans=0,
        )

    async def index_manifest(self) -> IndexHealth | None:
        try:
            manifest = await self.system.index.manifest()
        except Exception:
            return None
        return IndexHealth(
            model_id=manifest.model_id,
            dimensions=manifest.dimensions,
            record_count=manifest.record_count,
        )

    async def providers_report(self) -> tuple[ProviderHealth, ...]:
        embeddings = await self.system.embeddings.capabilities()
        generation = await self.system.generation_provider.capabilities()
        return (
            ProviderHealth(provider_id=embeddings.provider_id, available=True),
            ProviderHealth(provider_id=generation.provider_id, available=True),
        )

    async def usage(self) -> DiskUsage:
        return DiskUsage(free_bytes=self.free_bytes, total_bytes=50_000_000_000)

    async def ipc_report(self) -> IpcHealth:
        return IpcHealth(responsive=True, reason_code="in-process")


class KeyHealthAdapter:
    provider_id = "os-keyring"

    def __init__(self, system: LocalRecallSystem) -> None:
        self._system = system

    async def health(self, request: KeyRequest) -> object:
        del request
        return await self._system.key_provider.health(KeyRequest(purpose=KeyPurpose.RECORD))


def build_system_health_checks(
    system: LocalRecallSystem, *, free_bytes: int = 10_000_000_000
) -> tuple[HealthCheck, ...]:
    ports = SystemHealthPorts(system=system, free_bytes=free_bytes)
    return build_health_checks(
        lifecycle_state_port=ports,
        capture_backend_port=ports,
        metadata_sources_port=ports,
        ocr_port=ports,
        redaction_port=ports,
        key_provider=KeyHealthAdapter(system),
        storage_port=ports,
        index_port=ports,
        providers_port=ports,
        disk_port=ports,
        ipc_port=ports,
        min_free_bytes=1_000_000,
    )
