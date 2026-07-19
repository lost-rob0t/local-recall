from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.audit import (
    AuditAction,
    AuditCategory,
    AuditEvent,
    AuditFailure,
    AuditFailureCode,
    AuditFileSettings,
    AuditOutcome,
    AuditReasonCode,
    OwnerOnlyAuditFileSink,
)


def event() -> AuditEvent:
    return AuditEvent(
        category=AuditCategory.CAPTURE,
        action=AuditAction.CAPTURE_DECISION,
        outcome=AuditOutcome.SKIPPED,
        reason=AuditReasonCode.POLICY_DENY,
        correlation_id=uuid4(),
        occurred_at=datetime(2026, 7, 18, 12, tzinfo=UTC),
        record_id=uuid4(),
        generation=4,
        attributes={"queue_depth": 2},
    )


def test_sink_writes_canonical_owner_only_jsonl(tmp_path: Path) -> None:
    sink = OwnerOnlyAuditFileSink(AuditFileSettings(tmp_path / "audit"))
    sink.emit(event())
    sink.close()

    payload = json.loads(sink.path.read_text().strip())
    assert payload["schema_version"] == 1
    assert payload["reason"] == "policy_deny"
    assert os.stat(sink.path.parent).st_mode & 0o777 == 0o700
    assert os.stat(sink.path).st_mode & 0o777 == 0o600


def test_insecure_existing_directory_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o755)
    root.chmod(0o755)

    with pytest.raises(AuditFailure) as captured:
        OwnerOnlyAuditFileSink(AuditFileSettings(root))

    assert captured.value.code is AuditFailureCode.INSECURE_PERMISSIONS


def test_symlinked_log_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_text("synthetic-target")
    (root / "audit.jsonl").symlink_to(target)

    with pytest.raises(AuditFailure) as captured:
        OwnerOnlyAuditFileSink(AuditFileSettings(root))

    assert captured.value.code is AuditFailureCode.UNSAFE_PATH


def test_rotation_stays_bounded_and_owner_only(tmp_path: Path) -> None:
    sink = OwnerOnlyAuditFileSink(
        AuditFileSettings(
            tmp_path / "audit",
            max_file_bytes=4096,
            max_event_bytes=2048,
            max_files=2,
        )
    )
    for _ in range(40):
        sink.emit(event())
    sink.close()

    rotated = list(sink.path.parent.glob("audit.*.jsonl"))
    assert len(rotated) <= 2
    assert all(os.stat(path).st_mode & 0o777 == 0o600 for path in rotated)


def test_debug_path_uses_the_same_serializer(tmp_path: Path) -> None:
    sink = OwnerOnlyAuditFileSink(AuditFileSettings(tmp_path / "audit"))
    source = event()
    sink.emit_debug(source)
    sink.close()

    payload = json.loads(sink.path.read_text().strip())
    assert payload["event_id"] == str(source.event_id)
    assert set(payload) <= {
        "schema_version",
        "event_id",
        "correlation_id",
        "occurred_at",
        "category",
        "action",
        "outcome",
        "reason",
        "record_id",
        "generation",
        "provider_id",
        "key_version",
        "configuration_revision_digest",
        "key_id_digest",
        "attributes",
    }
