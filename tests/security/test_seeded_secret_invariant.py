from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4, uuid5

from local_recall.audit.file_sink import AuditFileSettings, OwnerOnlyAuditFileSink
from local_recall.audit.models import (
    AuditAction,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditReasonCode,
)
from local_recall.backup.archive import BackupArchive
from local_recall.crypto.envelope import EnvelopeCipher
from local_recall.crypto.keyring import OSKeyringProvider
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.health.bundle import build_diagnostic_bundle
from local_recall.health.models import (
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
)
from local_recall.storage import SQLiteEncryptedStorage

_NOW = datetime(2026, 8, 30, tzinfo=UTC)
# Deterministic per-run marker; reproducible seeds come from fixing the uuid.
SEEDED_SECRET = f"seeded-secret-{uuid5(uuid.NAMESPACE_URL, 'local-recall-issue-38')}"


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def _redacted_record_with_secret() -> RedactedRecord:
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=_NOW,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIX",
        metadata=ContextMetadata(observed_at=_NOW, fields=()),
        ocr_text=(SEEDED_SECRET,),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=uuid4(), frame=frame, created_at=_NOW)


def _scan_tree(root: Path) -> list[str]:
    hits: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            if SEEDED_SECRET.encode() in data:
                hits.append(str(path.name))
    return hits


def _encrypted_frames_envelope(provider: OSKeyringProvider) -> object:
    cipher = EnvelopeCipher()
    return asyncio.run(
        cipher.encrypt_frames(
            record_id=uuid4(),
            generation=CaptureGeneration(1),
            configuration_revision="config-v1",
            frames=(SEEDED_SECRET.encode(),),
            provider=provider,
            created_at=_NOW,
        )
    )


def test_seeded_secret_never_reaches_persisted_storage_files(tmp_path: Path) -> None:
    storage = SQLiteEncryptedStorage(
        tmp_path / "storage", quota_bytes=10_000_000, max_blob_bytes=1_000_000
    )
    provider = OSKeyringProvider(MemoryKeyringBackend())
    cipher = EnvelopeCipher()
    record = _redacted_record_with_secret()
    envelope = asyncio.run(
        cipher.encrypt_frames(
            record_id=record.record_id,
            generation=record.frame.generation,
            configuration_revision="config-v1",
            frames=(SEEDED_SECRET.encode(),),
            provider=provider,
            created_at=_NOW,
        )
    )
    asyncio.run(storage.put(envelope))

    assert _scan_tree(tmp_path) == []
    loaded = asyncio.run(storage.get(record.record_id))
    assert loaded is not None
    frames = asyncio.run(cipher.decrypt_frames(loaded, provider))
    assert frames == (SEEDED_SECRET.encode(),)
    assert _scan_tree(tmp_path) == []


def test_seeded_secret_never_reaches_audit_logs(tmp_path: Path) -> None:
    sink = OwnerOnlyAuditFileSink(
        AuditFileSettings(root=tmp_path / "audit", fsync_each_event=False)
    )
    event = AuditEvent(
        category=AuditCategory.RECORD,
        action=AuditAction.RECORD_REJECTED,
        outcome=AuditOutcome.REJECTED,
        reason=AuditReasonCode.INVALID_RECORD,
        correlation_id=uuid4(),
        occurred_at=_NOW,
        generation=1,
        attributes={"count": 1},
    )
    sink.emit(event)
    sink.close()
    assert _scan_tree(tmp_path) == []


def test_seeded_secret_never_reaches_backup_archives(tmp_path: Path) -> None:
    provider = OSKeyringProvider(MemoryKeyringBackend())
    envelope = _encrypted_frames_envelope(provider)
    assert isinstance(envelope, object)
    archive_path = tmp_path / "backup.bin"
    BackupArchive.write(
        archive_path,
        envelopes=(envelope,),  # type: ignore[arg-type]
        created_at=_NOW.isoformat(),
        schema_version=1,
        max_blob_bytes=1_000_000,
    )
    assert _scan_tree(tmp_path) == []


def test_hostile_shaped_reason_codes_cannot_enter_bundles(tmp_path: Path) -> None:
    report = HealthReport(
        results=(
            HealthCheckResult(
                check_id=HealthCheckId.REDACTION,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code=f"leaked content {SEEDED_SECRET}",
            ),
        )
    )
    try:
        bundle = build_diagnostic_bundle(
            report, now=lambda: _NOW, record_count=0, storage_bytes=0, revisions=()
        )
    except ValueError:
        assert not any(tmp_path.rglob("*"))
        return
    (tmp_path / "bundle.json").write_text(bundle.to_json(), encoding="utf-8")
    assert _scan_tree(tmp_path) == []


def test_bundle_accepts_fixed_shaped_reason_codes(tmp_path: Path) -> None:
    report = HealthReport(
        results=(
            HealthCheckResult(
                check_id=HealthCheckId.REDACTION,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code="selftest-failed",
            ),
        )
    )
    bundle = build_diagnostic_bundle(
        report, now=lambda: _NOW, record_count=0, storage_bytes=0, revisions=("policy-v4",)
    )
    (tmp_path / "bundle.json").write_text(bundle.to_json(), encoding="utf-8")
    assert "selftest-failed" in (tmp_path / "bundle.json").read_text(encoding="utf-8")
