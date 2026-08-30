from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.domain.frames import RedactedRecord
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.retention.engine import RetentionEngine
from local_recall.retention.planner import RetentionRules

from .harness import AdvanceClock, LocalRecallSystem, SyntheticDesktop

_START = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)
SOAK_CAPTURES = 120
CAPTURE_LATENCY_BUDGET_SECONDS = 0.5
QUERY_LATENCY_BUDGET_SECONDS = 2.0
MAX_BYTES_PER_RECORD = 16 * 1024


def _system(tmp_path: Path) -> LocalRecallSystem:
    clock = AdvanceClock(_START, step_seconds=30.0)
    return LocalRecallSystem(
        root=tmp_path,
        clock=clock,
        desktop=SyntheticDesktop(clock=clock.now),
    )


@pytest.mark.timeout(60)
def test_soak_bounded_queues_retention_and_latency_budgets(tmp_path: Path) -> None:
    system = _system(tmp_path)
    try:
        system.start()
        system.wait_recording()

        slowest = 0.0
        for index in range(SOAK_CAPTURES):
            started = time.monotonic()
            asyncio.run(system.capture_once())
            slowest = max(slowest, time.monotonic() - started)
            system.clock.advance()
            if index % 40 == 39:
                assert len(system.records) == system.indexed_count()

        assert slowest < CAPTURE_LATENCY_BUDGET_SECONDS, slowest
        assert len(system.records) == SOAK_CAPTURES
        assert system.indexed_count() == SOAK_CAPTURES

        usage = system.usage()
        assert usage.ready_records == SOAK_CAPTURES
        assert usage.ready_bytes < SOAK_CAPTURES * MAX_BYTES_PER_RECORD

        query_started = time.monotonic()
        answer = asyncio.run(system.ask("What was I doing today?", now=_START))
        assert time.monotonic() - query_started < QUERY_LATENCY_BUDGET_SECONDS
        assert answer.insufficient_evidence is False

        engine = RetentionEngine(
            storage=system.storage,
            encryption=_NeverEncryptGuard(),
            rules=RetentionRules(max_age_days=1, max_bytes=10_000_000, max_records=64),
            today=(_START + timedelta(days=3)).date(),
        )
        report = asyncio.run(engine.sweep())
        assert report.deleted_count > 0
        assert system.usage().ready_records < SOAK_CAPTURES
    finally:
        system.shutdown()


class _NeverEncryptGuard:
    provider_id = "soak-decryptor"

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        raise AssertionError("retention sweep must never decrypt record payloads")

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        raise AssertionError("retention sweep must never encrypt")
