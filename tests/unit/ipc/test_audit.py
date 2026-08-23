from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from local_recall.audit import AuditAction, AuditCategory, AuditEvent, AuditRecorder
from local_recall.audit.adapters import IpcAuditAdapter


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def test_ipc_audit_records_closed_operational_metadata_only() -> None:
    sink = MemorySink()
    recorder = AuditRecorder(sink, clock=lambda: datetime(2026, 8, 23, tzinfo=UTC))
    audit = IpcAuditAdapter(recorder)
    correlation_id = uuid4()

    event = audit.accepted(
        capability="query",
        urgent=False,
        correlation_id=correlation_id,
    )

    assert event.category is AuditCategory.IPC
    assert event.action is AuditAction.IPC_REQUEST
    assert event.correlation_id == correlation_id
    assert event.attributes == {
        "authorized": True,
        "control": False,
        "diagnostic": False,
        "query": True,
        "urgent": False,
    }


def test_ipc_audit_cannot_carry_content_bearing_values() -> None:
    marker = "SYNTHETIC-IPC-PRIVATE-MARKER"
    sink = MemorySink()
    recorder = AuditRecorder(sink)
    audit = IpcAuditAdapter(recorder)

    event = audit.rejected(capability="control", urgent=True)
    rendered = repr(event)

    assert marker not in rendered
    assert "token" not in rendered.lower()
    assert "socket" not in rendered.lower()
    assert "request_text" not in rendered.lower()
    assert event.attributes == {
        "authorized": False,
        "control": True,
        "diagnostic": False,
        "query": False,
        "urgent": True,
    }
