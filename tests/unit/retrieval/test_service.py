from __future__ import annotations

import asyncio
import importlib
from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Protocol, cast
from uuid import UUID, uuid4

from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyHandle,
    StoredRecordRef,
)
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.ports.storage import CatalogRecord, DayRangeQuery, DeleteRequest, DeleteResult
from local_recall.retrieval.time import ResolvedTimeRange


class _Passage(Protocol):
    record_id: UUID
    captured_at: datetime
    excerpt: str
    score: float
    redaction_policy_revision: str
    redaction_finding_count: int
    metadata_provenance: tuple[_FieldProvenance, ...]


class _FieldProvenance(Protocol):
    field_name: str
    source_id: str
    confidence: float


class _Batch(Protocol):
    passages: tuple[_Passage, ...]
    remote_provider_eligible: bool
    policy_revision: str


class _Service(Protocol):
    async def retrieve(self, query: object) -> _Batch: ...


type _ServiceFactory = Callable[..., _Service]
type _QueryFactory = Callable[..., object]
type _DecisionFactory = Callable[..., object]


def _api() -> tuple[_ServiceFactory, _QueryFactory, _DecisionFactory]:
    module = importlib.import_module("local_recall.retrieval.service")
    return (
        cast(_ServiceFactory, module.__dict__["RetrievalService"]),
        cast(_QueryFactory, module.__dict__["RetrievalQuery"]),
        cast(_DecisionFactory, module.__dict__["RetrievalPolicyDecision"]),
    )


class FakeStorage:
    backend_id = "fake-storage"

    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self.records = {record.record_id: record for record in records}
        self.envelopes = {record.record_id: _envelope(record) for record in records}
        self.list_requests: list[DayRangeQuery] = []

    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        self.list_requests.append(request)
        return tuple(
            CatalogRecord(
                record=StoredRecordRef(record_id, self.backend_id, 1),
                day_bucket=record.frame.captured_at.astimezone(UTC).date(),
                blob_bytes=128,
                key_provider_id="fake-key-provider",
                key_id="record-key",
                key_version=1,
            )
            for record_id, record in self.records.items()
        )

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        return self.envelopes.get(record_id)

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        self.envelopes[envelope.record_id] = envelope
        return StoredRecordRef(envelope.record_id, self.backend_id, envelope.schema_version)

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        deleted = self.envelopes.pop(request.record_id, None) is not None
        return DeleteResult(request.record_id, deleted, False)

    async def recover(self) -> object:
        return object()


class FakeEncryption:
    provider_id = "fake-encryption"

    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self.records = {record.record_id: record for record in records}
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        self.decrypted.append(request.envelope.record_id)
        return self.records[request.envelope.record_id]

    async def encrypt(
        self, request: EncryptionRequest[RedactedRecord]
    ) -> EncryptedRecordEnvelope:
        del request
        raise AssertionError("retrieval must never encrypt")


class FakePolicy:
    def __init__(self, decision: object) -> None:
        self.decision = decision
        self.query_checks = 0
        self.record_checks = 0

    async def authorize_query(self, query: object) -> object:
        del query
        self.query_checks += 1
        return self.decision

    async def authorize_record(self, query: object, record: RedactedRecord) -> object:
        del query, record
        self.record_checks += 1
        return self.decision


def test_retrieval_uses_coarse_catalog_then_exact_redacted_filters() -> None:
    service_type, query_type, decision_type = _api()
    inside = _record(
        datetime(2026, 8, 22, 10, 30, tzinfo=UTC),
        application="emacs",
        workspace="dev",
        text="reviewed prolog retrieval design",
    )
    wrong_application = _record(
        datetime(2026, 8, 22, 11, 0, tzinfo=UTC),
        application="browser",
        workspace="dev",
        text="prolog documentation",
    )
    outside_exact_range = _record(
        datetime(2026, 8, 22, 13, 0, tzinfo=UTC),
        application="emacs",
        workspace="dev",
        text="prolog after lunch",
    )
    records = (inside, wrong_application, outside_exact_range)
    storage = FakeStorage(records)
    encryption = FakeEncryption(records)
    policy = FakePolicy(
        decision_type(
            allowed=True,
            remote_provider_eligible=False,
            policy_revision="query-policy-v1",
            reason_code="allowed",
        )
    )
    service = service_type(storage=storage, encryption=encryption, policy=policy)
    query = query_type(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        ),
        application="emacs",
        workspace="dev",
        keywords=("prolog",),
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert len(storage.list_requests) == 1
    assert storage.list_requests[0].start_day == date(2026, 8, 22)
    assert storage.list_requests[0].end_day == date(2026, 8, 22)
    assert storage.list_requests[0].limit == 100
    assert set(encryption.decrypted) == {record.record_id for record in records}
    assert tuple(item.record_id for item in result.passages) == (inside.record_id,)
    passage = result.passages[0]
    assert passage.captured_at == inside.frame.captured_at
    assert passage.excerpt == "reviewed prolog retrieval design"
    assert passage.redaction_policy_revision == "redaction-policy-v1"
    assert passage.redaction_finding_count == 0
    assert any(
        item.field_name == "application"
        and item.source_id == "synthetic-metadata"
        and item.confidence == 0.9
        for item in passage.metadata_provenance
    )
    assert not result.remote_provider_eligible
    assert result.policy_revision == "query-policy-v1"
    assert policy.query_checks == 1
    assert policy.record_checks == 1
    assert "reviewed prolog retrieval design" not in repr(passage)
    assert "PIXEL-SECRET" not in repr(passage)


def test_query_policy_denial_prevents_catalog_access_and_decryption() -> None:
    service_type, query_type, decision_type = _api()
    record = _record(
        datetime(2026, 8, 22, 10, 30, tzinfo=UTC),
        application="emacs",
        workspace="dev",
        text="private retained text",
    )
    storage = FakeStorage((record,))
    encryption = FakeEncryption((record,))
    policy = FakePolicy(
        decision_type(
            allowed=False,
            remote_provider_eligible=False,
            policy_revision="query-policy-v1",
            reason_code="privacy-mode",
        )
    )
    service = service_type(storage=storage, encryption=encryption, policy=policy)
    query = query_type(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        ),
        limit=10,
        candidate_limit=100,
    )

    result = asyncio.run(service.retrieve(query))

    assert result.passages == ()
    assert storage.list_requests == []
    assert encryption.decrypted == []
    assert not result.remote_provider_eligible
    assert result.policy_revision == "query-policy-v1"
    assert policy.query_checks == 1
    assert policy.record_checks == 0


def _record(
    captured_at: datetime,
    *,
    application: str,
    workspace: str,
    text: str,
) -> RedactedRecord:
    record_id = uuid4()
    provenance = MetadataProvenance(
        source_id="synthetic-metadata",
        observed_at=captured_at,
        confidence=SourceConfidence(0.9),
        adapter_revision="test-v1",
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
        pixels=b"PIX",
        metadata=metadata,
        ocr_text=(text,),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=record_id, frame=frame, created_at=captured_at)


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
