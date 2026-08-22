from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

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
from local_recall.retrieval.service import (
    RetrievalPolicyDecision,
    RetrievalQuery,
    RetrievalService,
)
from local_recall.retrieval.time import ResolvedTimeRange
from local_recall.storage import SQLiteEncryptedStorage


class Decryptor:
    provider_id = "integration-decryptor"

    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self._records = {record.record_id: record for record in records}
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        self.decrypted.append(request.envelope.record_id)
        return self._records[request.envelope.record_id]

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


def test_encrypted_catalog_narrows_then_exact_filters_run_after_decryption(tmp_path: Path) -> None:
    wanted = _record(datetime(2026, 8, 22, 10, 30, tzinfo=UTC), "emacs", "dev")
    wrong_app = _record(datetime(2026, 8, 22, 10, 45, tzinfo=UTC), "browser", "dev")
    outside_day = _record(datetime(2026, 8, 23, 10, 30, tzinfo=UTC), "emacs", "dev")
    records = (wanted, wrong_app, outside_day)
    storage = SQLiteEncryptedStorage(tmp_path, quota_bytes=1_000_000, max_blob_bytes=100_000)
    for record in records:
        asyncio.run(storage.put(_envelope(record)))
    decryptor = Decryptor(records)
    service = RetrievalService(storage=storage, encryption=decryptor, policy=Policy())
    query = RetrievalQuery(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 11, 0, tzinfo=UTC),
        ),
        application="emacs",
        workspace="dev",
        keywords=("retrieval",),
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert set(decryptor.decrypted) == {wanted.record_id, wrong_app.record_id}
    assert outside_day.record_id not in decryptor.decrypted
    assert tuple(item.record_id for item in result.passages) == (wanted.record_id,)
    assert result.passages[0].captured_at == wanted.frame.captured_at
    assert result.passages[0].redaction_policy_revision == "redaction-policy-v1"
    assert any(
        item.field_name == "application"
        and item.source_id == "synthetic-metadata"
        and item.confidence == 0.9
        for item in result.passages[0].metadata_provenance
    )


def _record(
    captured_at: datetime,
    application: str,
    workspace: str,
) -> RedactedRecord:
    provenance = MetadataProvenance(
        source_id="synthetic-metadata",
        observed_at=captured_at,
        confidence=SourceConfidence(0.9),
        adapter_revision="integration-v1",
    )
    metadata = ContextMetadata(
        observed_at=captured_at,
        fields=(
            ContextField("application", application, (provenance,)),
            ContextField("workspace", workspace, (provenance,)),
        ),
    )
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=captured_at,
        width=1,
        height=1,
        stride=3,
        pixel_format=PixelFormat.RGB8,
        pixels=b"REDACTED-PIXELS",
        metadata=metadata,
        ocr_text=("retrieval boundary evidence",),
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
        key=KeyHandle("record-key", "integration-key-provider", 1),
        plaintext_frame_sizes=(1,),
        wrapped_data_key=b"w" * 48,
        nonce=b"n" * 24,
        ciphertext=b"synthetic-ciphertext",
        associated_data_digest=b"d" * 32,
        created_at=record.created_at,
    )
