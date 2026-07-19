from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from local_recall.audit import (
    AuditEvent,
    AuditFailure,
    AuditFileSettings,
    AuditReasonCode,
    AuditRecorder,
    OwnerOnlyAuditFileSink,
)


_SEEDED_VALUES = (
    "synthetic-window-title-seed",
    "synthetic-ocr-text-seed",
    "https://synthetic.invalid/private",
    "synthetic-command --token synthetic-token-seed",
    "synthetic-user-name",
    "synthetic-provider-prompt-seed",
)


def test_audit_log_contains_no_seeded_content_or_secret_values(tmp_path: Path) -> None:
    sink = OwnerOnlyAuditFileSink(AuditFileSettings(tmp_path / "audit"))
    recorder = AuditRecorder(sink, clock=lambda: datetime(2026, 7, 18, tzinfo=UTC))

    recorder.lifecycle_transition(
        reason=AuditReasonCode.STARTUP_OPT_IN,
        generation=1,
        correlation_id=uuid4(),
        configuration_revision=_SEEDED_VALUES[0],
        faulted=False,
    )
    recorder.key_operation(
        reason=AuditReasonCode.KEY_CREATED,
        key_id=_SEEDED_VALUES[1],
        key_version=1,
        succeeded=True,
        provider_id="os-keyring",
    )
    recorder.capture_decision(
        record_id=uuid4(),
        generation=1,
        accepted=False,
        reason=AuditReasonCode.POLICY_DENY,
        attributes={"queue_depth": 0},
    )
    sink.close()

    persisted = sink.path.read_text()
    assert all(value not in persisted for value in _SEEDED_VALUES)
    assert "configuration_revision_digest" in persisted
    assert "key_id_digest" in persisted


def test_arbitrary_debug_reason_cannot_bypass_the_schema(tmp_path: Path) -> None:
    sink = OwnerOnlyAuditFileSink(AuditFileSettings(tmp_path / "audit"))
    with pytest.raises(AuditFailure):
        sink.emit_debug(
            cast(
                AuditEvent,
                {
                    "reason": _SEEDED_VALUES[2],
                    "message": _SEEDED_VALUES[3],
                },
            )
        )
    sink.close()
    assert sink.path.read_bytes() == b""
