from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import pytest

from local_recall.audit import (
    AuditAction,
    AuditCategory,
    AuditEvent,
    AuditFailure,
    AuditOutcome,
    AuditReasonCode,
    AuditRecorder,
)


class MemorySink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def test_event_rejects_arbitrary_reason_text() -> None:
    with pytest.raises(AuditFailure):
        AuditEvent(
            category=AuditCategory.CAPTURE,
            action=AuditAction.CAPTURE_DECISION,
            outcome=AuditOutcome.REJECTED,
            reason=cast(AuditReasonCode, "synthetic-window-title-seed"),
            correlation_id=uuid4(),
            occurred_at=datetime.now(UTC),
        )


def test_event_rejects_unapproved_attribute_keys() -> None:
    with pytest.raises(AuditFailure):
        AuditEvent(
            category=AuditCategory.CAPTURE,
            action=AuditAction.CAPTURE_DECISION,
            outcome=AuditOutcome.REJECTED,
            reason=AuditReasonCode.POLICY_DENY,
            correlation_id=uuid4(),
            occurred_at=datetime.now(UTC),
            attributes={"window_title": 1},
        )


def test_recorder_hashes_key_and_configuration_references() -> None:
    sink = MemorySink()
    recorder = AuditRecorder(sink, clock=lambda: datetime(2026, 7, 18, tzinfo=UTC))

    key_event = recorder.key_operation(
        reason=AuditReasonCode.KEY_ROTATED,
        key_id="synthetic-sensitive-key-reference",
        key_version=2,
        succeeded=True,
        provider_id="os-keyring",
    )
    lifecycle_event = recorder.lifecycle_transition(
        reason=AuditReasonCode.STARTUP_OPT_IN,
        generation=4,
        correlation_id=uuid4(),
        configuration_revision="synthetic-configuration-revision",
        faulted=False,
    )

    assert key_event.key_id_digest is not None
    assert key_event.key_id_digest != "synthetic-sensitive-key-reference"
    assert lifecycle_event.configuration_revision_digest is not None
    assert (
        lifecycle_event.configuration_revision_digest
        != "synthetic-configuration-revision"
    )
    assert len(sink.events) == 2


def test_repr_contains_no_hashed_source_values() -> None:
    sink = MemorySink()
    recorder = AuditRecorder(sink)
    event = recorder.key_operation(
        reason=AuditReasonCode.KEY_CREATED,
        key_id="never-render-this-key-reference",
        key_version=1,
        succeeded=True,
        provider_id="local-keyring",
    )

    assert "never-render-this-key-reference" not in repr(event)
    assert "key_id_digest" not in repr(event)
