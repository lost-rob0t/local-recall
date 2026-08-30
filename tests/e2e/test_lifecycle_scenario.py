from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path

from local_recall.lifecycle import PauseCapture, ResumeCapture
from local_recall.lifecycle.messages import LifecycleCommandResult
from typing import cast

from .harness import AdvanceClock, LocalRecallSystem, SyntheticDesktop

_START = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)


def _system(tmp_path: Path) -> LocalRecallSystem:
    clock = AdvanceClock(_START)
    return LocalRecallSystem(
        root=tmp_path, clock=clock, desktop=SyntheticDesktop(clock=clock.now)
    )


def test_lifecycle_scenario_start_record_pause_resume_stop_restart_query(tmp_path: Path) -> None:
    system = _system(tmp_path)
    try:
        started = time.monotonic()
        system.start()
        system.wait_recording()
        assert time.monotonic() - started < 2.0

        first = asyncio.run(system.capture_once())
        assert first.frame.ocr_text == ("emacs project-notes",)
        count_after_first = system.usage().ready_records
        assert count_after_first == 1

        cast(LifecycleCommandResult, system.actor_ref.ask(PauseCapture(), timeout=2))
        assert system.gate.snapshot().state.value == "paused"
        paused_count = system.usage().ready_records

        cast(LifecycleCommandResult, system.actor_ref.ask(ResumeCapture(), timeout=2))
        assert system.gate.snapshot().state.value == "recording"
        assert system.usage().ready_records == paused_count

        stopped_at = time.monotonic()
        system.stop()
        assert system.gate.snapshot().state.value == "off"
        assert time.monotonic() - stopped_at < 2.0
        assert system.usage().ready_records == paused_count

        system.start()
        system.wait_recording()
        second = asyncio.run(system.capture_once())
        assert second.frame.ocr_text == ("emacs project-notes",)

        answer = asyncio.run(system.ask("What was I doing today?", now=_START))
        assert answer.insufficient_evidence is False
        assert answer.claims
        citations = answer.claims[0].citations
        assert citations
        assert all(item.record_id is not None for item in citations)
    finally:
        system.shutdown()


def test_stop_halts_persistence_within_bounded_time(tmp_path: Path) -> None:
    system = _system(tmp_path)
    try:
        system.start()
        system.wait_recording()
        asyncio.run(system.capture_once())
        before_stop = system.usage().ready_records

        stop_started = time.monotonic()
        system.stop()
        elapsed = time.monotonic() - stop_started
        assert elapsed < 2.0

        import pytest

        from local_recall.lifecycle import CaptureGateClosed

        with pytest.raises(CaptureGateClosed):
            system.gate.run_capture(lambda permit: permit)
        assert system.usage().ready_records == before_stop
    finally:
        system.shutdown()
