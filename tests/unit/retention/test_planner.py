from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.retention.planner import (
    ContextRetentionRule,
    RetentionPlanner,
    RetentionRules,
    ScopeBudgetExceeded,
)
from local_recall.storage import SQLiteEncryptedStorage


def _record(index: int, *, captured_at: datetime, application: str | None = None) -> RedactedRecord:
    fields: tuple[ContextField, ...] = ()
    if application is not None:
        provenance = MetadataProvenance(
            source_id="synthetic-metadata",
            observed_at=captured_at,
            confidence=SourceConfidence(0.9),
            adapter_revision="integration-v1",
        )
        fields = (ContextField("application", application, (provenance,)),)
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIX",
        metadata=ContextMetadata(observed_at=captured_at, fields=fields),
        ocr_text=(f"retention-entry-{index}",),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=uuid4(), frame=frame, created_at=captured_at)


def _envelope(record: RedactedRecord) -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=record.record_id,
        generation=record.frame.generation,
        configuration_revision="config-v1",
        schema_version=1,
        algorithm="test-only",
        key=KeyHandle("record-key", "fake-key-provider", 1),
        plaintext_frame_sizes=(1,),
        wrapped_data_key=b"wrapped",
        nonce=b"nonce",
        ciphertext=b"ciphertext",
        associated_data_digest=b"digest",
        created_at=record.created_at,
    )


class Decryptor:
    provider_id = "retention-decryptor"

    def __init__(self, records: dict[UUID, RedactedRecord]) -> None:
        self._records = records
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        record = self._records[request.envelope.record_id]
        self.decrypted.append(record.record_id)
        return record

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        raise AssertionError("retention must never encrypt")


def _storage(tmp_path: Path, records: list[RedactedRecord]) -> SQLiteEncryptedStorage:
    storage = SQLiteEncryptedStorage(
        tmp_path / "storage", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    for record in records:
        asyncio.run(storage.put(_envelope(record)))
    return storage


_TODAY = date(2026, 8, 30)


def test_storage_exposes_usage_and_keyset_pages(tmp_path: Path) -> None:
    old = _record(1, captured_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC))
    new = _record(2, captured_at=datetime(2026, 8, 29, 10, 0, tzinfo=UTC))
    storage = _storage(tmp_path, [old, new])

    usage = asyncio.run(storage.stats())

    assert usage.ready_records == 2
    assert usage.ready_bytes > 0

    first_page = asyncio.run(storage.page_ready(limit=1))
    assert len(first_page.entries) == 1
    assert first_page.entries[0].day_bucket == date(2026, 1, 1)
    assert first_page.complete is False

    second_page = asyncio.run(
        storage.page_ready(
            after_day=first_page.entries[0].day_bucket,
            after_id=first_page.entries[0].record_id,
            limit=1,
        )
    )
    assert len(second_page.entries) == 1
    assert second_page.entries[0].record_id == new.record_id


def test_planner_dry_run_selects_expired_records_without_deleting(tmp_path: Path) -> None:
    expired_a = _record(1, captured_at=datetime(2026, 1, 5, 10, 0, tzinfo=UTC))
    expired_b = _record(2, captured_at=datetime(2026, 1, 6, 10, 0, tzinfo=UTC))
    fresh = _record(3, captured_at=datetime(2026, 8, 29, 10, 0, tzinfo=UTC))
    storage = _storage(tmp_path, [expired_a, expired_b, fresh])
    decryptor = Decryptor({r.record_id: r for r in (expired_a, expired_b, fresh)})
    planner = RetentionPlanner(
        storage=storage,
        encryption=decryptor,
        rules=RetentionRules(max_age_days=30, max_bytes=1_000_000_000, max_records=250_000),
        today=_TODAY,
    )

    plan = asyncio.run(planner.plan(dry_run=True))

    assert plan.dry_run is True
    assert set(plan.expired) == {expired_a.record_id, expired_b.record_id}
    assert plan.evicted == ()
    assert asyncio.run(storage.get(expired_a.record_id)) is not None
    assert asyncio.run(storage.stats()).ready_records == 3


def test_planner_evicts_oldest_first_only_under_watermark(tmp_path: Path) -> None:
    records = [
        _record(
            index + 1,
            captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC) + timedelta(minutes=index),
        )
        for index in range(4)
    ]
    storage = _storage(tmp_path, records)
    usage = asyncio.run(storage.stats())
    decryptor = Decryptor({r.record_id: r for r in records})
    budget = usage.ready_bytes
    page = asyncio.run(storage.page_ready(limit=10_000))
    smallest = min(entry.blob_bytes for entry in page.entries)

    below = RetentionPlanner(
        storage=storage,
        encryption=decryptor,
        rules=RetentionRules(max_age_days=3650, max_bytes=budget * 2, max_records=250_000),
        today=_TODAY,
    )
    calm = asyncio.run(below.plan(dry_run=True))
    assert calm.evicted == ()

    above = RetentionPlanner(
        storage=storage,
        encryption=decryptor,
        rules=RetentionRules(
            max_age_days=3650,
            max_bytes=budget - 1,
            low_watermark_bytes=budget - smallest,
            max_records=250_000,
        ),
        today=_TODAY,
    )
    pressured = asyncio.run(above.plan(dry_run=True))

    ordered = sorted(records, key=lambda r: (r.created_at.astimezone(UTC).date(), str(r.record_id)))
    assert pressured.evicted[0] == ordered[0].record_id
    assert ordered[0].record_id in pressured.evicted
    assert ordered[-1].record_id not in pressured.evicted


def test_planner_enforces_record_count_cap_oldest_first(tmp_path: Path) -> None:
    records = [
        _record(
            index + 1,
            captured_at=datetime(2026, 8, 20, 10, 0, tzinfo=UTC) + timedelta(minutes=index),
        )
        for index in range(5)
    ]
    storage = _storage(tmp_path, records)
    decryptor = Decryptor({r.record_id: r for r in records})
    planner = RetentionPlanner(
        storage=storage,
        encryption=decryptor,
        rules=RetentionRules(max_age_days=3650, max_bytes=1_000_000_000, max_records=3),
        today=_TODAY,
    )

    plan = asyncio.run(planner.plan(dry_run=True))

    ordered = sorted(records, key=lambda r: (r.created_at.astimezone(UTC).date(), str(r.record_id)))
    assert set(plan.evicted) == {ordered[0].record_id, ordered[1].record_id}
    assert len(plan.expired) == 0


def test_planner_context_rules_keep_named_application_longer(tmp_path: Path) -> None:
    browser_old = _record(
        1, captured_at=datetime(2026, 6, 1, 10, 0, tzinfo=UTC), application="firefox"
    )
    emacs_old = _record(2, captured_at=datetime(2026, 6, 1, 11, 0, tzinfo=UTC), application="emacs")
    browser_new = _record(
        3, captured_at=datetime(2026, 8, 29, 10, 0, tzinfo=UTC), application="firefox"
    )
    storage = _storage(tmp_path, [browser_old, emacs_old, browser_new])
    decryptor = Decryptor({r.record_id: r for r in (browser_old, emacs_old, browser_new)})
    planner = RetentionPlanner(
        storage=storage,
        encryption=decryptor,
        rules=RetentionRules(
            max_age_days=30,
            max_bytes=1_000_000_000,
            max_records=250_000,
            context_rules=(
                ContextRetentionRule(field_name="application", value="emacs", max_age_days=180),
            ),
        ),
        today=_TODAY,
    )

    plan = asyncio.run(planner.plan(dry_run=True))

    assert browser_old.record_id in plan.expired
    assert browser_new.record_id not in plan.expired
    assert emacs_old.record_id not in plan.expired
    assert set(decryptor.decrypted) == {browser_old.record_id, emacs_old.record_id}


def test_planner_context_rules_expire_named_application_sooner(tmp_path: Path) -> None:
    ephemeral = _record(
        1, captured_at=datetime(2026, 8, 10, 10, 0, tzinfo=UTC), application="temp-viewer"
    )
    keeper = _record(2, captured_at=datetime(2026, 8, 10, 11, 0, tzinfo=UTC), application="emacs")
    storage = _storage(tmp_path, [ephemeral, keeper])
    decryptor = Decryptor({r.record_id: r for r in (ephemeral, keeper)})
    planner = RetentionPlanner(
        storage=storage,
        encryption=decryptor,
        rules=RetentionRules(
            max_age_days=30,
            max_bytes=1_000_000_000,
            max_records=250_000,
            context_rules=(
                ContextRetentionRule(field_name="application", value="temp-viewer", max_age_days=3),
            ),
        ),
        today=_TODAY,
    )

    plan = asyncio.run(planner.plan(dry_run=True))

    assert set(plan.expired) == {ephemeral.record_id}
    assert set(decryptor.decrypted) == {ephemeral.record_id, keeper.record_id}


def test_planner_fails_closed_when_decrypt_budget_exceeded(tmp_path: Path) -> None:
    first = _record(1, captured_at=datetime(2026, 8, 10, 10, 0, tzinfo=UTC), application="a")
    second = _record(2, captured_at=datetime(2026, 8, 10, 11, 0, tzinfo=UTC), application="b")
    storage = _storage(tmp_path, [first, second])
    decryptor = Decryptor({r.record_id: r for r in (first, second)})
    planner = RetentionPlanner(
        storage=storage,
        encryption=decryptor,
        rules=RetentionRules(
            max_age_days=3,
            max_bytes=1_000_000_000,
            max_records=250_000,
            context_rules=(
                ContextRetentionRule(field_name="application", value="a", max_age_days=300),
            ),
        ),
        today=_TODAY,
        decrypt_budget=1,
    )

    with pytest.raises(ScopeBudgetExceeded, match="budget"):
        asyncio.run(planner.plan(dry_run=True))


def test_planner_rejects_invalid_rules() -> None:
    with pytest.raises(ValueError, match="watermark"):
        RetentionRules(max_age_days=30, max_bytes=1000, low_watermark_bytes=2000, max_records=10)
    with pytest.raises(ValueError, match="field"):
        ContextRetentionRule(field_name="url_history", value="x", max_age_days=1)
    with pytest.raises(ValueError, match="value"):
        ContextRetentionRule(field_name="application", value="", max_age_days=1)
