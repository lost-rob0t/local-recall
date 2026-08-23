from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, StoredRecordRef
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.ports.storage import CatalogRecord, DayRangeQuery, DeleteRequest, DeleteResult
from local_recall.retrieval.service import (
    RetrievalPolicyDecision,
    RetrievalQuery,
    RetrievalService,
)
from local_recall.retrieval.time import ResolvedTimeRange


class RaceStorage:
    backend_id = "race-storage"

    def __init__(self, record: RedactedRecord) -> None:
        self.record = record
        self.envelope: EncryptedRecordEnvelope | None = _envelope(record)
        self.get_calls = 0

    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        del request
        return (
            CatalogRecord(
                record=StoredRecordRef(self.record.record_id, self.backend_id, 1),
                day_bucket=self.record.frame.captured_at.date(),
                blob_bytes=128,
                key_provider_id="fake-key-provider",
                key_id="record-key",
                key_version=1,
            ),
        )

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        assert record_id == self.record.record_id
        self.get_calls += 1
        return self.envelope

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        assert request.record_id == self.record.record_id
        deleted = self.envelope is not None
        self.envelope = None
        return DeleteResult(request.record_id, deleted, False)

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        self.envelope = envelope
        return StoredRecordRef(envelope.record_id, self.backend_id, envelope.schema_version)

    async def recover(self) -> object:
        return object()


class DeleteDuringDecrypt:
    provider_id = "race-encryption"

    def __init__(self, storage: RaceStorage, record: RedactedRecord) -> None:
        self.storage = storage
        self.record = record

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        await self.storage.delete(DeleteRequest(request.envelope.record_id, "race-delete"))
        return self.record

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        del request
        raise AssertionError("retrieval must never encrypt")


class AllowPolicy:
    async def authorize_query(self, query: RetrievalQuery) -> RetrievalPolicyDecision:
        del query
        return _allowed()

    async def authorize_record(
        self, query: RetrievalQuery, record: RedactedRecord
    ) -> RetrievalPolicyDecision:
        del query, record
        return _allowed()


def test_record_deleted_after_decryption_cannot_escape_retrieval() -> None:
    captured_at = datetime(2026, 8, 22, 10, 30, tzinfo=UTC)
    record = _record(captured_at)
    storage = RaceStorage(record)
    service = RetrievalService(
        storage=storage,
        encryption=DeleteDuringDecrypt(storage, record),
        policy=AllowPolicy(),
    )
    query = RetrievalQuery(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        ),
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert result.passages == ()
    assert storage.get_calls >= 2


def _allowed() -> RetrievalPolicyDecision:
    return RetrievalPolicyDecision(
        allowed=True,
        remote_provider_eligible=False,
        policy_revision="query-policy-v1",
        reason_code="allowed",
    )


def _record(captured_at: datetime) -> RedactedRecord:
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"PIX",
        metadata=ContextMetadata(observed_at=captured_at, fields=()),
        ocr_text=("must-not-escape-after-delete",),
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
