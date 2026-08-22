from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.retrieval.service import RetrievalQuery, RetrievalService
from local_recall.retrieval.time import ResolvedTimeRange

from .test_metadata_filters import Policy, Storage


class CancellingEncryption:
    provider_id = "cancelling-test"

    def __init__(self) -> None:
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        self.decrypted.append(request.envelope.record_id)
        raise asyncio.CancelledError

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        del request
        raise AssertionError("retrieval must never encrypt")


def _record() -> RedactedRecord:
    captured_at = datetime(2026, 8, 22, 11, 0, tzinfo=UTC)
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
        ocr_text=("redacted activity",),
        findings=(),
        policy_revision="redaction-policy-v1",
    )
    return RedactedRecord(record_id=uuid4(), frame=frame, created_at=captured_at)


def test_cancellation_propagates_without_partial_batch() -> None:
    first = _record()
    second = _record()
    encryption = CancellingEncryption()
    service = RetrievalService(
        storage=Storage((first, second)),
        encryption=encryption,
        policy=Policy(),
    )
    query = RetrievalQuery(
        time_range=ResolvedTimeRange(
            datetime(2026, 8, 22, 10, 0, tzinfo=UTC),
            datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        ),
        limit=10,
        candidate_limit=100,
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(service.retrieve(query))

    assert len(encryption.decrypted) == 1
