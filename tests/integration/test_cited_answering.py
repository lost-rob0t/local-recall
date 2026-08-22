from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from local_recall.answering.models import AnswerMode
from local_recall.answering.rendering import render_answer
from local_recall.answering.service import AnsweringService
from local_recall.domain import (
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
)
from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.retrieval.service import (
    RetrievalPolicyDecision,
    RetrievalQuery,
    RetrievalService,
    SemanticCandidate,
)
from local_recall.routing import RoutingMode, RoutingPolicy
from local_recall.storage import SQLiteEncryptedStorage

SATURDAY_MORNING = datetime(2026, 8, 22, 14, 0, tzinfo=UTC)
SATURDAY_AFTERNOON = datetime(2026, 8, 22, 18, 0, tzinfo=UTC)
SUNDAY = datetime(2026, 8, 23, 14, 0, tzinfo=UTC)
NOW = datetime(2026, 8, 24, 15, 30, tzinfo=UTC)


class Decryptor:
    provider_id = "integration-decryptor"

    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self._records = {record.record_id: record for record in records}

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        return self._records[request.envelope.record_id]

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        del request
        raise AssertionError("answer retrieval must never encrypt")


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
    def __init__(self, records: tuple[RedactedRecord, ...]) -> None:
        self._records = records

    async def search(
        self,
        text: str,
        *,
        start_at: datetime,
        end_at: datetime,
        limit: int,
    ) -> tuple[SemanticCandidate, ...]:
        assert "What was I doing" in text
        matches = tuple(
            SemanticCandidate(record.record_id, record.frame.captured_at, 0.91)
            for record in self._records
            if start_at <= record.frame.captured_at < end_at
        )
        return matches[:limit]


class LocalProvider:
    def __init__(self, expected_ids: tuple[UUID, UUID]) -> None:
        self.expected_ids = expected_ids
        self.requests: list[GenerationRequest] = []

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="local-answer",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=64 * 1024,
            supports_vision=False,
            supports_structured_output=True,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        self.requests.append(request)
        serialized = "\n".join(request.context)
        assert all(str(record_id) not in serialized for record_id in self.expected_ids)
        return GenerationResponse(
            text=(
                '{"claims":['
                '{"kind":"observed","text":"Reviewed the roadmap.","evidence_ids":["E1"]},'
                '{"kind":"observed","text":"Edited the design document.","evidence_ids":["E2"]}'
                "]}"
            ),
            provider_id="local-answer",
            model_id="fixture-model",
        )


def test_saturday_question_reads_encrypted_records_and_returns_chronological_citations(
    tmp_path: Path,
) -> None:
    morning = _record(SATURDAY_MORNING, "Reviewed the roadmap.")
    afternoon = _record(SATURDAY_AFTERNOON, "Edited the design document.")
    sunday = _record(SUNDAY, "This Sunday record must not be retrieved.")
    records = (morning, afternoon, sunday)
    storage = SQLiteEncryptedStorage(tmp_path, quota_bytes=1_000_000, max_blob_bytes=100_000)
    for record in records:
        asyncio.run(storage.put(_envelope(record)))

    retrieval = RetrievalService(
        storage=storage,
        encryption=Decryptor(records),
        policy=Policy(),
        semantic_search=SemanticSearch(records),
    )
    provider = LocalProvider((morning.record_id, afternoon.record_id))
    service = AnsweringService(
        retrieval=retrieval,
        routing=RoutingPolicy(RoutingMode.LOCAL_ONLY),
        local_providers=(provider,),
    )

    answer = asyncio.run(
        service.answer(
            "What was I doing Saturday?",
            now=NOW,
            timezone="America/New_York",
            mode=AnswerMode.TIMELINE,
        )
    )
    rendered = render_answer(answer)

    assert answer.insufficient_evidence is False
    assert tuple(claim.citations[0].record_id for claim in answer.claims) == (
        morning.record_id,
        afternoon.record_id,
    )
    assert SATURDAY_MORNING.isoformat() in rendered
    assert SATURDAY_AFTERNOON.isoformat() in rendered
    assert str(sunday.record_id) not in rendered
    assert len(provider.requests) == 1


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
        metadata=ContextMetadata(observed_at=captured_at, fields=()),
        ocr_text=(text,),
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
