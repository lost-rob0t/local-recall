from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from local_recall.activity import reconcile as activity_reconcile
from local_recall.activity.clustering import ActivityClusteringPolicy, ActivitySegmenter
from local_recall.activity.features import ActivityFeatureExtractor
from local_recall.activity.store import EncryptedActivityStore
from local_recall.activity.summaries import ActivitySummarizer
from local_recall.crypto import OSKeyringProvider
from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, StoredRecordRef
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    ProviderCapabilities,
)
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.ports.storage import (
    CatalogRecord,
    DayRangeQuery,
    DeleteRequest,
    DeleteResult,
    StorageIntegrityReport,
)
from local_recall.timeline.activity_rebuild import (
    SurvivingRecordActivityReconciler,
    TimelineRebuildFailure,
)


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


class Embeddings:
    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="local-embedding",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.EMBEDDING}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=65_536,
            supports_vision=False,
        )

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        return EmbeddingResponse(
            provider_id="local-embedding",
            model_id="embed-v1",
            vectors=tuple((1.0, 0.0) for _ in request.inputs),
        )


class Generator:
    def __init__(self) -> None:
        self.calls = 0

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="local-generation",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=65_536,
            supports_vision=False,
            supports_structured_output=True,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        self.calls += 1
        source_id = re.findall(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            request.prompt,
        )[0]
        return GenerationResponse(
            provider_id="local-generation",
            model_id="summary-v1",
            text='{"evidence":[{"source_id":"' + source_id + '","excerpt":"surviving"}]}',
        )


class FakeStorage:
    backend_id = "rebuild-storage"

    def __init__(self, *records: RedactedRecord) -> None:
        self.records: dict[UUID, RedactedRecord] = {r.record_id: r for r in records}
        self._present: set[UUID] = set(self.records)
        self.deleted: list[UUID] = []

    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        found: list[CatalogRecord] = []
        for record_id, record in self.records.items():
            if record_id not in self._present:
                continue
            captured_day = record.frame.captured_at.astimezone(UTC).date()
            if request.start_day <= captured_day <= request.end_day:
                found.append(
                    CatalogRecord(
                        record=StoredRecordRef(record_id, self.backend_id, 1),
                        day_bucket=captured_day,
                        blob_bytes=128,
                        key_provider_id="fake-key-provider",
                        key_id="record-key",
                        key_version=1,
                    )
                )
        return tuple(sorted(found, key=lambda item: (item.day_bucket, str(item.record.record_id))))

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        if record_id not in self._present:
            return None
        return _envelope(self.records[record_id])

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        deleted = request.record_id in self._present
        self._present.discard(request.record_id)
        self.deleted.append(request.record_id)
        return DeleteResult(request.record_id, deleted, False)

    async def put(self, envelope: EncryptedRecordEnvelope):
        raise AssertionError("activity rebuild must never encrypt")

    async def recover(self) -> StorageIntegrityReport:
        return StorageIntegrityReport()


class FakeEncryption:
    provider_id = "rebuild-encryption"

    def __init__(self, records: dict[UUID, RedactedRecord]) -> None:
        self.records = records
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        record = self.records[request.envelope.record_id]
        self.decrypted.append(record.record_id)
        return record

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        raise AssertionError("activity rebuild must never encrypt")


def _record(
    index: int,
    *,
    captured_at: datetime,
    text: str,
) -> RedactedRecord:
    frame = RedactedFrame(
        frame_id=UUID(int=index),
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
    return RedactedRecord(record_id=UUID(int=index), frame=frame, created_at=captured_at)


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


class Harness:
    def __init__(
        self,
        tmp_path: Path,
        *records: RedactedRecord,
        candidate_limit: int = 10_000,
    ) -> None:
        self.storage = FakeStorage(*records)
        self.encryption = FakeEncryption(self.storage.records)
        self.generator = Generator()
        self.root = tmp_path / "activity"
        self.store = EncryptedActivityStore(self.root, OSKeyringProvider(MemoryKeyringBackend()))
        self.reconciler = activity_reconcile.ActivityReconciler(
            feature_extractor=ActivityFeatureExtractor(Embeddings()),
            segmenter=ActivitySegmenter(
                ActivityClusteringPolicy(
                    max_gap_seconds=600.0,
                    strong_gap_seconds=120.0,
                    minimum_continuity_score=0.5,
                    minimum_semantic_similarity=0.5,
                )
            ),
            summarizer=ActivitySummarizer(self.generator),
            store=self.store,
        )
        self.adapter = SurvivingRecordActivityReconciler(
            storage=self.storage,
            encryption=self.encryption,
            reconciler=self.reconciler,
            store=self.store,
            candidate_limit=candidate_limit,
        )

    def seed(self, *records: RedactedRecord) -> None:
        asyncio.run(self.reconciler.reconcile(records))

    @property
    def member_ids(self) -> set[UUID] | None:
        snapshot = asyncio.run(self.store.load())
        if snapshot is None:
            return None
        return {
            record_id for entry in snapshot.entries for record_id in entry.cluster.source_record_ids
        }


def test_rebuild_excludes_deleted_records_and_keeps_survivors(tmp_path: Path) -> None:
    base = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    first = _record(1, captured_at=base, text="delete-me-secret-marker")
    second = _record(2, captured_at=base + timedelta(minutes=1), text="survivor-two")
    third = _record(3, captured_at=base + timedelta(minutes=2), text="survivor-three")
    harness = Harness(tmp_path, first, second, third)
    harness.seed(first, second, third)
    assert len(asyncio.run(harness.store.load()).entries) == 1  # type: ignore[union-attr]

    asyncio.run(harness.storage.delete(DeleteRequest(first.record_id, "selective-delete")))
    asyncio.run(harness.adapter.reconcile_deleted((first.record_id,)))

    members = harness.member_ids
    assert members is not None
    assert first.record_id not in members
    assert members == {second.record_id, third.record_id}
    assert harness.encryption.decrypted == [second.record_id, third.record_id]
    assert harness.generator.calls >= 1


def test_rebuild_scans_only_snapshot_window(tmp_path: Path) -> None:
    base = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    inside = _record(1, captured_at=base, text="inside-window")
    outside = _record(2, captured_at=base + timedelta(days=30), text="outside-window")
    harness = Harness(tmp_path, inside, outside)
    harness.seed(inside)

    asyncio.run(harness.storage.delete(DeleteRequest(inside.record_id, "selective-delete")))
    asyncio.run(harness.adapter.reconcile_deleted((inside.record_id,)))

    assert outside.record_id not in harness.encryption.decrypted


def test_rebuild_skips_records_deleted_concurrently(tmp_path: Path) -> None:
    base = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    first = _record(1, captured_at=base, text="concurrent-victim")
    second = _record(2, captured_at=base + timedelta(minutes=1), text="concurrent-survivor")
    harness = Harness(tmp_path, first, second)
    harness.seed(first, second)

    asyncio.run(harness.adapter.reconcile_deleted((first.record_id, uuid4())))

    assert harness.member_ids == {first.record_id, second.record_id}


def test_rebuild_fails_closed_when_candidates_exceed_limit(tmp_path: Path) -> None:
    base = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    first = _record(1, captured_at=base, text="limit-record-one")
    second = _record(2, captured_at=base + timedelta(minutes=1), text="limit-record-two")
    harness = Harness(tmp_path, first, second, candidate_limit=1)
    harness.seed(first, second)

    try:
        asyncio.run(harness.adapter.reconcile_deleted((first.record_id,)))
    except TimelineRebuildFailure as exc:
        assert "candidate" in str(exc)
    else:
        raise AssertionError("candidate overflow must fail closed")

    members = harness.member_ids
    assert members == {first.record_id, second.record_id}


def test_rebuild_writes_no_plaintext_artifacts(tmp_path: Path) -> None:
    base = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    first = _record(1, captured_at=base, text="PLAINTEXT-MARKER-XYZ")
    second = _record(2, captured_at=base + timedelta(minutes=1), text="PLAINTEXT-MARKER-ABC")
    harness = Harness(tmp_path, first, second)
    harness.seed(first, second)

    asyncio.run(harness.storage.delete(DeleteRequest(first.record_id, "selective-delete")))
    asyncio.run(harness.adapter.reconcile_deleted((first.record_id,)))

    for path in harness.root.rglob("*"):
        if path.is_file():
            assert b"PLAINTEXT-MARKER" not in path.read_bytes()


def test_rebuild_requires_explicit_unique_scope(tmp_path: Path) -> None:
    base = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    first = _record(1, captured_at=base, text="scope-record")
    harness = Harness(tmp_path, first)

    for invalid in ((), (first.record_id, first.record_id)):
        try:
            asyncio.run(harness.adapter.reconcile_deleted(invalid))
        except ValueError as exc:
            assert "record" in str(exc).lower()
        else:
            raise AssertionError("empty or duplicate scopes must be rejected")
