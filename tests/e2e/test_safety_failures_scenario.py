from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from local_recall.crypto.errors import EncryptionFailure
from local_recall.crypto.keyring import KeyringBackendLocked
from local_recall.health.checks import build_health_checks
from local_recall.health.guard import PrivacyDependencyFault, ensure_persistence_allowed
from local_recall.health.models import HealthCheckId, HealthState
from local_recall.health.service import HealthService
from local_recall.index.semantic import IndexFailure
from local_recall.domain.lifecycle import TransitionReason
from local_recall.lifecycle import LifecycleCommandResult, PauseCapture
from local_recall.ports.keys import KeyHealthStatus
from typing import cast

from .health_ports import KeyHealthAdapter, SystemHealthPorts
from .harness import (
    AdvanceClock,
    LocalRecallSystem,
    MemoryKeyringBackend,
    SyntheticDesktop,
)

_START = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)


class ScenarioKeyringBackend(MemoryKeyringBackend):
    def __init__(self) -> None:
        super().__init__()
        self.locked = False

    def get_password(self, service: str, username: str) -> str | None:
        if self.locked:
            raise KeyringBackendLocked("synthetic-keyring-lock")
        return super().get_password(service, username)


def _system(tmp_path: Path, *, key_backend: MemoryKeyringBackend | None = None) -> LocalRecallSystem:
    clock = AdvanceClock(_START)
    return LocalRecallSystem(
        root=tmp_path,
        clock=clock,
        desktop=SyntheticDesktop(clock=clock.now),
        key_backend=key_backend,
    )


def test_session_lock_pauses_capture_and_halts_persistence(tmp_path: Path) -> None:
    system = _system(tmp_path)
    try:
        system.start()
        system.wait_recording()
        asyncio.run(system.capture_once())
        count_before = system.usage().ready_records

        result = cast(
            LifecycleCommandResult,
            system.actor_ref.ask(PauseCapture(reason=TransitionReason.SESSION_LOCKED), timeout=2),
        )
        assert result.snapshot.state.value == "paused"
        assert system.gate.snapshot().privacy_mode is False
        assert system.usage().ready_records == count_before
    finally:
        system.shutdown()


def test_key_lock_reports_capture_blocking_and_stops_encryption(tmp_path: Path) -> None:
    backend = ScenarioKeyringBackend()
    system = _system(tmp_path, key_backend=backend)
    try:
        system.start()
        system.wait_recording()
        asyncio.run(system.capture_once())
        records_before = len(system.records)
        backend.locked = True

        ports = SystemHealthPorts(system=system)
        checks = build_health_checks(
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
        report = asyncio.run(HealthService(checks=checks, per_check_timeout_seconds=2.0).report())
        keys = report.check(HealthCheckId.ENCRYPTION_KEYS)
        assert keys is not None
        assert keys.state is HealthState.CAPTURE_BLOCKING
        assert keys.reason_code == "key-locked"
        assert report.check(HealthCheckId.ENCRYPTION_KEYS) is not None
        from local_recall.ports.keys import KeyHealthStatus as _Status

        assert _Status.LOCKED is KeyHealthStatus.LOCKED

        with pytest.raises(PrivacyDependencyFault):
            ensure_persistence_allowed(report)

        with pytest.raises(EncryptionFailure):
            asyncio.run(system.capture_once())
        assert len(system.records) == records_before
    finally:
        system.shutdown()


def test_low_disk_is_reported_as_capture_blocking(tmp_path: Path) -> None:
    system = _system(tmp_path)
    try:
        system.start()
        system.wait_recording()
        asyncio.run(system.capture_once())

        ports = SystemHealthPorts(system=system, free_bytes=500)
        checks = build_health_checks(
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
        report = asyncio.run(HealthService(checks=checks, per_check_timeout_seconds=2.0).report())
        disk = report.check(HealthCheckId.DISK_QUOTA)
        assert disk is not None
        assert disk.state is HealthState.CAPTURE_BLOCKING
        with pytest.raises(PrivacyDependencyFault):
            ensure_persistence_allowed(report)
    finally:
        system.shutdown()


def test_corrupted_index_is_detected_and_rebuild_repair_recovers(tmp_path: Path) -> None:
    system = _system(tmp_path)
    try:
        system.start()
        system.wait_recording()
        asyncio.run(system.capture_once())
        assert system.indexed_count() == 1

        active = system.root / "index" / "semantic-index.lri"
        active.write_bytes(b"corrupted-payload")

        with pytest.raises(IndexFailure):
            asyncio.run(system.index.manifest())

        asyncio.run(system.index.rebuild(tuple(system.index_documents), system.embeddings))
        assert system.indexed_count() == 1
    finally:
        system.shutdown()


def test_model_outage_degrades_answers_without_stopping_capture(tmp_path: Path) -> None:
    system = _system(tmp_path)
    try:
        system.start()
        system.wait_recording()
        asyncio.run(system.capture_once())

        async def broken_capabilities() -> object:
            raise RuntimeError("synthetic-model-outage")

        system.generation_provider.capabilities = broken_capabilities  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            asyncio.run(system.ask("What was I doing today?", now=_START))

        captured = asyncio.run(system.capture_once())
        assert captured.frame.ocr_text == ("emacs project-notes",)
    finally:
        system.shutdown()
