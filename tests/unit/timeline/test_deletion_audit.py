from __future__ import annotations

import threading
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.errors import AuditFailure
from local_recall.audit.models import AuditAction, AuditCategory, AuditOutcome, AuditReasonCode
from local_recall.timeline.scope import DeletionScopeKind


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self.lock:
            self.events.append(event)


def _recorder() -> tuple[AuditRecorder, MemorySink]:
    sink = MemorySink()
    return AuditRecorder(sink), sink


def test_deletion_request_event_is_sanitized_and_content_free() -> None:
    recorder, sink = _recorder()

    recorder.deletion_request(
        scope_kind=DeletionScopeKind.APPLICATION,
        count=3,
        succeeded=True,
        correlation_id=uuid4(),
    )

    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.category is AuditCategory.RECORD
    assert event.action is AuditAction.DELETION_REQUEST
    assert event.outcome is AuditOutcome.SUCCEEDED
    assert event.reason is AuditReasonCode.DELETION_COMPLETED
    assert event.attributes == {
        "records": False,
        "cluster": False,
        "application": True,
        "time_range": False,
        "success": True,
        "count": 3,
    }


def test_deletion_request_failure_event_uses_failed_outcome() -> None:
    recorder, sink = _recorder()

    recorder.deletion_request(
        scope_kind=DeletionScopeKind.TIME_RANGE,
        count=0,
        succeeded=False,
        correlation_id=uuid4(),
    )

    event = sink.events[0]
    assert event.outcome is AuditOutcome.FAILED
    assert event.attributes["success"] is False


def test_deletion_request_requires_single_scope_class() -> None:
    _, sink = _recorder()

    with pytest.raises(AuditFailure):
        AuditEvent(
            category=AuditCategory.RECORD,
            action=AuditAction.DELETION_REQUEST,
            outcome=AuditOutcome.SUCCEEDED,
            reason=AuditReasonCode.DELETION_COMPLETED,
            correlation_id=uuid4(),
            occurred_at=datetime.now(UTC),
            attributes={
                "records": False,
                "cluster": False,
                "application": False,
                "time_range": False,
                "success": True,
                "count": 1,
            },
        )
    assert sink.events == []


def test_deletion_request_event_rejects_content_bearing_fields() -> None:

    with pytest.raises(AuditFailure):
        AuditEvent(
            category=AuditCategory.RECORD,
            action=AuditAction.DELETION_REQUEST,
            outcome=AuditOutcome.SUCCEEDED,
            reason=AuditReasonCode.DELETION_COMPLETED,
            correlation_id=uuid4(),
            occurred_at=datetime.now(UTC),
            attributes={
                "records": True,
                "cluster": False,
                "application": False,
                "time_range": False,
                "success": True,
                "count": 1,
                "window_title": 1,
            },
        )
