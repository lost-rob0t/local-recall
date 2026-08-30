from __future__ import annotations

import pytest

from local_recall.audit import AuditRecorder
from local_recall.audit.errors import AuditFailure
from local_recall.audit.models import AuditAction, AuditCategory, AuditEvent, AuditOutcome


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def test_health_check_action_is_audited_as_system_event() -> None:
    recorder = AuditRecorder(MemorySink())
    event = recorder.record_health_check(healthy=True)
    assert event.category is AuditCategory.SYSTEM
    assert event.action is AuditAction.HEALTH_CHECK
    assert event.outcome is AuditOutcome.SUCCEEDED


def test_repair_operation_requires_exact_attributes() -> None:
    recorder = AuditRecorder(MemorySink())
    event = recorder.record_repair_operation(
        command="index-rebuild", succeeded=True, restartable=True, count=4
    )
    assert event.action is AuditAction.REPAIR_OPERATION
    assert event.outcome is AuditOutcome.SUCCEEDED
    with pytest.raises(AuditFailure):
        recorder.record_repair_operation(
            command="index-rebuild", succeeded=True, restartable=True, count=-1
        )


def test_repair_failure_is_recorded_as_failed() -> None:
    sink = MemorySink()
    recorder = AuditRecorder(sink)
    event = recorder.record_repair_operation(
        command="orphan-cleanup", succeeded=False, restartable=True, count=0
    )
    assert event.outcome is AuditOutcome.FAILED
    assert sink.events == [event]
