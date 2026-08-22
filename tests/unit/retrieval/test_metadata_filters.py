from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, StoredRecordRef
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.ports.storage import (
    CatalogRecord,
    DayRangeQuery,
    DeleteRequest,
    DeleteResult,
    StorageIntegrityReport,
)
from local_recall.retrieval.service import (
    MetadataFilter,
    RetrievalPolicyDecision,
    RetrievalQuery,
    RetrievalService,
)
from local_recall.retrieval.time import ResolvedTimeRange

_SCREEN_SENTINEL = 987654321


class Storage:
    backend_id = "metadata-test"

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
        )

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        return self.envelopes.get(record_id)

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        return StoredRecordRef(envelope.record_id, self.backend_id, envelope.schema_version)

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        return DeleteResult(request.record_id, False, False)

    async def recover(self) -> StorageIntegrityReport:
        return StorageIntegrityReport(verified_records=len(self.envelopes))


class Encryption:
    provider_id = "metadata-test"

    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self.records = {record.record_id: record for record in records}

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        return self.records[request.envelope.record_id]

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
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


def test_metadata_filters_match_only_decrypted_redacted_metadata() -> None:
    wanted = _record("max", _SCREEN_SENTINEL)
    other = _record("columns", _SCREEN_SENTINEL)
    service = RetrievalService(
        storage=Storage((wanted, other)),
        encryption=Encryption((wanted, other)),
        policy=Policy(),
    )
    query = RetrievalQuery(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        ),
        metadata_filters=(
            MetadataFilter("layout", "max"),
            MetadataFilter("screen", _SCREEN_SENTINEL),
        ),
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert tuple(item.record_id for item in result.passages) == (wanted.record_id,)
    assert "max" not in repr(query)
    assert str(_SCREEN_SENTINEL) not in repr(query)
    assert "metadata_filter_count=2" in repr(query)


def _record(layout: str, screen: int) -> RedactedRecord:
    captured_at = datetime(2026, 8, 22, 11, 0, tzinfo=UTC)
    provenance = MetadataProvenance(
        "synthetic-metadata", captured_at, SourceConfidence(0.9), "test-v1"
    )
    metadata = ContextMetadata(
        captured_at,
        (
            ContextField("layout", layout, (provenance,)),
            ContextField("screen", screen, (provenance,)),
        ),
    )
    frame = RedactedFrame(
        uuid4(),
        CaptureGeneration(1),
        captured_at,
        1,
        1,
        3,
        PixelFormat.RGB8,
        b"PIX",
        metadata,
        ("redacted activity",),
        (),
        "redaction-policy-v1",
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
