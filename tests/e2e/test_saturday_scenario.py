from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from local_recall.domain.frames import RedactedRecord
from local_recall.domain.privacy import PrivacyClass

from .harness import AdvanceClock, DesktopWindow, LocalRecallSystem, SyntheticDesktop

MONDAY = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
SATURDAY = datetime(2026, 8, 22, 14, 0, tzinfo=UTC)
SUNDAY = datetime(2026, 8, 23, 15, 0, tzinfo=UTC)


def _build(tmp_path: Path) -> LocalRecallSystem:
    clock = AdvanceClock(SATURDAY)
    windows = [
        DesktopWindow("emacs", "Reviewed the roadmap for the release"),
        DesktopWindow("chromium", "Read the spec discussion"),
    ]
    desktop = SyntheticDesktop(clock=clock.now, windows=windows)
    return LocalRecallSystem(root=tmp_path, clock=clock, desktop=desktop)


def test_what_was_i_doing_saturday_answers_with_saturday_citations(tmp_path: Path) -> None:
    system = _build(tmp_path)
    try:
        system.start()
        system.wait_recording()

        saturday_records: list[RedactedRecord] = []
        for _ in range(2):
            saturday_records.append(asyncio.run(system.capture_once()))
            system.clock.advance()
        assert all(
            record.frame.captured_at.date() == SATURDAY.date() for record in saturday_records
        )

        system.clock.jump_to(SUNDAY)
        sunday_record = asyncio.run(system.capture_once())
        assert sunday_record.frame.captured_at.date() == SUNDAY.date()

        system.clock.jump_to(MONDAY)
        monday_record = asyncio.run(system.capture_once())
        assert monday_record.frame.captured_at.date() == MONDAY.date()
        assert system.usage().ready_records == 4

        answer = asyncio.run(system.ask("What was I doing Saturday?", now=MONDAY))

        assert answer.insufficient_evidence is False
        assert answer.claims
        citations = [item for claim in answer.claims for item in claim.citations]
        assert citations
        assert all(item.captured_at.date() == SATURDAY.date() for item in citations), [
            item.captured_at for item in citations
        ]
        assert all(item.record_id is not None for item in citations)
        assert system.generation_provider.requests[0].privacy_class is PrivacyClass.REDACTED_CONTENT
    finally:
        system.shutdown()
