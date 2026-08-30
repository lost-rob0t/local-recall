from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from local_recall.activity import reconcile as activity_reconcile
from local_recall.activity.clustering import ActivityClusteringPolicy, ActivitySegmenter
from local_recall.activity.features import ActivityFeatureExtractor
from local_recall.activity.store import EncryptedActivityStore
from local_recall.activity.summaries import ActivitySummarizer
from local_recall.crypto import OSKeyringProvider
from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, StoredRecordRef
from local_recall.domain.frames import PixelFormat, RedactedFrame, RedactedRecord
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
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
from local_recall.timeline.scope import (
    DeletionScope,
    DeletionScopeKind,
    DeletionScopeResolver,
    ScopeResolutionFailure,
    cluster_identifier,
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


class NullGenerator:
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

    async def generate(self, request):
        del request
        raise AssertionError("scope resolution must never summarize")


class FakeStorage:
    backend_id = "scope-storage"

    def __init__(self, *records: RedactedRecord) -> None:
        self.records: dict[UUID, RedactedRecord] = {r.record_id: r for r in records}
        self._present: set[UUID] = set(self.records)
        self.list_calls: list[DayRangeQuery] = []

    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        self.list_calls.append(request)
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
        return DeleteResult(request.record_id, deleted, False)

    async def put(self, envelope: EncryptedRecordEnvelope):
        raise AssertionError("scope resolution must never encrypt")

    async def recover(self) -> StorageIntegrityReport:
        return StorageIntegrityReport()


class FakeEncryption:
    provider_id = "scope-encryption"

    def __init__(self, records: dict[UUID, RedactedRecord]) -> None:
        self._records = records
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        record = self._records[request.envelope.record_id]
        self.decrypted.append(record.record_id)
        return record

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        raise AssertionError("scope resolution must never encrypt")


_BASE = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)


def _record(
    index: int,
    *,
    captured_at: datetime,
    text: str,
    application: str | None = None,
) -> RedactedRecord:
    metadata = ContextMetadata(observed_at=captured_at, fields=())
    if application is not None:
        field_provenance = (
            MetadataProvenance(
                source_id="synthetic",
                observed_at=captured_at,
                confidence=SourceConfidence(1.0),
                adapter_revision="test-v1",
            ),
        )
        metadata = ContextMetadata(
            observed_at=captured_at,
            fields=(ContextField("application", application, field_provenance),),
        )
    frame = RedactedFrame(
        frame_id=UUID(int=index),
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
    def __init__(self, tmp_path: Path, *records: RedactedRecord) -> None:
        self.storage = FakeStorage(*records)
        self.encryption = FakeEncryption(self.storage.records)
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
            summarizer=ActivitySummarizer(NullGenerator()),
            store=self.store,
        )
        self.resolver = DeletionScopeResolver(
            storage=self.storage,
            encryption=self.encryption,
            activity_store=self.store,
        )

    def seed(self, *records: RedactedRecord) -> None:
        asyncio.run(self.reconciler.reconcile(records))


def test_record_scope_requires_explicit_unique_ids() -> None:
    first = UUID(int=1)
    second = UUID(int=2)

    scope = DeletionScope.for_records((first, second))
    assert scope.kind is DeletionScopeKind.RECORD_IDS

    with pytest.raises(ValueError, match="at least one"):
        DeletionScope.for_records(())
    with pytest.raises(ValueError, match="duplicate"):
        DeletionScope.for_records((first, first))


def test_time_range_scope_resolves_exact_capture_bounds(tmp_path: Path) -> None:
    early = _record(1, captured_at=_BASE, text="too-early")
    inside = _record(2, captured_at=_BASE + timedelta(minutes=30), text="inside-window")
    late = _record(3, captured_at=_BASE + timedelta(hours=5), text="too-late")
    harness = Harness(tmp_path, early, inside, late)

    scope = DeletionScope.for_time_range(
        start_at=_BASE + timedelta(minutes=10),
        end_at=_BASE + timedelta(hours=1),
    )
    resolved = asyncio.run(harness.resolver.resolve(scope))

    assert resolved == (inside.record_id,)
    assert harness.encryption.decrypted == [early.record_id, inside.record_id, late.record_id]


def test_time_range_scope_requires_aware_bounded_window() -> None:
    with pytest.raises(ValueError, match="time"):
        DeletionScope.for_time_range(start_at=_BASE, end_at=_BASE)
    with pytest.raises(ValueError, match="time"):
        DeletionScope.for_time_range(
            start_at=_BASE,
            end_at=_BASE + timedelta(days=400),
        )
    with pytest.raises(ValueError, match="timezone"):
        DeletionScope.for_time_range(
            start_at=datetime(2026, 8, 22, 10, 0),
            end_at=datetime(2026, 8, 22, 11, 0),
        )


def test_application_scope_selects_matching_records_within_bounds(tmp_path: Path) -> None:
    target = _record(1, captured_at=_BASE, text="emacs-note", application="Emacs")
    other_app = _record(2, captured_at=_BASE + timedelta(minutes=1), text="web-note")
    other_time = _record(3, captured_at=_BASE + timedelta(days=5), text="later-emacs")
    harness = Harness(tmp_path, target, other_app, other_time)
    harness.seed(target, other_app, other_time)

    scope = DeletionScope.for_application(
        "emacs",
        start_at=_BASE - timedelta(minutes=1),
        end_at=_BASE + timedelta(hours=1),
    )
    resolved = asyncio.run(harness.resolver.resolve(scope))

    assert resolved == (target.record_id,)
    assert other_time.record_id not in harness.encryption.decrypted


def test_cluster_scope_resolves_snapshot_membership(tmp_path: Path) -> None:
    first = _record(1, captured_at=_BASE, text="cluster-one")
    second = _record(2, captured_at=_BASE + timedelta(minutes=1), text="cluster-two")
    harness = Harness(tmp_path, first, second)
    harness.seed(first, second)
    snapshot = asyncio.run(harness.store.load())
    assert snapshot is not None and len(snapshot.entries) == 1
    identifier = cluster_identifier(snapshot.entries[0])

    scope = DeletionScope.for_cluster(identifier)
    assert scope.kind is DeletionScopeKind.ACTIVITY_CLUSTER
    resolved = asyncio.run(harness.resolver.resolve(scope))

    assert resolved == (first.record_id, second.record_id)

    unknown = DeletionScope.for_cluster("0" * 32)
    with pytest.raises(ScopeResolutionFailure, match="unknown"):
        asyncio.run(harness.resolver.resolve(unknown))


def test_scope_resolution_fails_closed_without_matches(tmp_path: Path) -> None:
    target = _record(1, captured_at=_BASE, text="unmatched-note", application="emacs")
    harness = Harness(tmp_path, target)

    empty_range = DeletionScope.for_time_range(
        start_at=_BASE + timedelta(hours=9),
        end_at=_BASE + timedelta(hours=10),
    )
    with pytest.raises(ScopeResolutionFailure, match="no records"):
        asyncio.run(harness.resolver.resolve(empty_range))

    empty_app = DeletionScope.for_application(
        "firefox",
        start_at=_BASE - timedelta(minutes=1),
        end_at=_BASE + timedelta(minutes=1),
    )
    with pytest.raises(ScopeResolutionFailure, match="no records"):
        asyncio.run(harness.resolver.resolve(empty_app))


def test_scope_resolution_fails_closed_on_candidate_overflow(tmp_path: Path) -> None:
    first = _record(1, captured_at=_BASE, text="overflow-one")
    second = _record(2, captured_at=_BASE + timedelta(minutes=1), text="overflow-two")
    harness = Harness(tmp_path, first, second)
    harness.resolver = DeletionScopeResolver(
        storage=harness.storage,
        encryption=harness.encryption,
        activity_store=harness.store,
        candidate_limit=1,
    )

    scope = DeletionScope.for_time_range(
        start_at=_BASE - timedelta(minutes=1),
        end_at=_BASE + timedelta(minutes=2),
    )
    with pytest.raises(ScopeResolutionFailure, match="candidate"):
        asyncio.run(harness.resolver.resolve(scope))


def test_scope_repr_and_payload_never_expose_application_text() -> None:
    scope = DeletionScope.for_application(
        "PRIVATE-APP-MARKER-9f21",
        start_at=_BASE,
        end_at=_BASE + timedelta(hours=1),
    )
    assert "PRIVATE-APP-MARKER-9f21" not in repr(scope)
    assert scope.application == "PRIVATE-APP-MARKER-9f21"
