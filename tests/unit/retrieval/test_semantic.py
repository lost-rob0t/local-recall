from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime
from uuid import UUID, uuid4

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, StoredRecordRef
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.ports.encryption import DecryptionRequest
from local_recall.ports.storage import CatalogRecord, DayRangeQuery
from local_recall.retrieval.service import (
    RetrievalPolicyDecision,
    RetrievalQuery,
    RetrievalService,
    SemanticCandidate,
)
from local_recall.retrieval.time import ResolvedTimeRange


class Storage:
    backend_id = "semantic-test"

    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self.records = {record.record_id: record for record in records}
        self.envelopes = {record.record_id: _envelope(record) for record in records}

    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        return tuple(
            CatalogRecord(
                StoredRecordRef(record.record_id, self.backend_id, 1),
                record.frame.captured_at.astimezone(UTC).date(),
                128,
                "fake-key-provider",
                "record-key",
                1,
            )
            for record in self.records.values()
            if request.start_day <= record.frame.captured_at.astimezone(UTC).date() <= request.end_day
        )

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        return self.envelopes.get(record_id)


class Decryptor:
    provider_id = "fake"

    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self.records = {record.record_id: record for record in records}
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        self.decrypted.append(request.envelope.record_id)
        return self.records[request.envelope.record_id]

    async def encrypt(self, request: object) -> EncryptedRecordEnvelope:
        del request
        raise AssertionError("retrieval must never encrypt")


class Policy:
    async def authorize_query(self, query: RetrievalQuery) -> RetrievalPolicyDecision:
        del query
        return RetrievalPolicyDecision(True, False, "query-policy-v1", "allowed")

    async def authorize_record(
        self, query: RetrievalQuery, record: RedactedRecord
    ) -> RetrievalPolicyDecision:
        del query, record
        return RetrievalPolicyDecision(True, False, "query-policy-v1", "allowed")


class SemanticSearch:
    def __init__(self, hits: tuple[SemanticCandidate, ...]) -> None:
        self.hits = hits
        self.queries: list[tuple[str, datetime, datetime, int]] = []

    async def search(
        self, text: str, *, start_at: datetime, end_at: datetime, limit: int
    ) -> tuple[SemanticCandidate, ...]:
        self.queries.append((text, start_at, end_at, limit))
        return self.hits


def test_semantic_hits_narrow_decryption_and_cannot_resurrect_deleted_records() -> None:
    first = _record(datetime(2026, 8, 22, 10, 0, tzinfo=UTC), "editor work")
    selected = _record(datetime(2026, 8, 22, 11, 0, tzinfo=UTC), "retrieval architecture")
    third = _record(datetime(2026, 8, 22, 12, 0, tzinfo=UTC), "browser research")
    records = (first, selected, third)
    stale_id = uuid4()
    semantic = SemanticSearch(
        (
            SemanticCandidate(selected.record_id, selected.frame.captured_at, 0.91),
            SemanticCandidate(stale_id, selected.frame.captured_at, 0.99),
        )
    )
    decryptor = Decryptor(records)
    service = RetrievalService(
        storage=Storage(records),
        encryption=decryptor,
        policy=Policy(),
        semantic_search=semantic,
    )
    time_range = ResolvedTimeRange(
        datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
        datetime(2026, 8, 22, 13, 0, tzinfo=UTC),
    )
    query = RetrievalQuery(
        time_range=time_range,
        semantic_text="architecture work",
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert semantic.queries == [("architecture work", time_range.start_at, time_range.end_at, 100)]
    assert decryptor.decrypted == [selected.record_id]
    assert tuple(item.record_id for item in result.passages) == (selected.record_id,)
    assert result.passages[0].score == 0.91
    assert stale_id not in {item.record_id for item in result.passages}
    assert "architecture work" not in repr(query)


def _record(captured_at: datetime, text: str) -> RedactedRecord:
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIX",
        metadata=ContextMetadata(captured_at, ()),
        ocr_text=(text,),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(uuid4(), frame, captured_at)


def _envelope(record: RedactedRecord) -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record.record_id,
        record.frame.generation,
        "config-v1",
        1,
        "test-only",
        KeyHandle("record-key", "fake-key-provider", 1),
        (1,),
        b"wrapped",
        b"nonce",
        b"ciphertext",
        b"digest",
        record.created_at,
    )
