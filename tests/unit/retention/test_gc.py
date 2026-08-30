from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from local_recall.activity import reconcile as activity_reconcile
from local_recall.activity.clustering import ActivityClusteringPolicy, ActivitySegmenter
from local_recall.activity.features import ActivityFeatureExtractor
from local_recall.activity.store import EncryptedActivityStore
from local_recall.activity.summaries import ActivitySummarizer
from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.models import AuditAction
from local_recall.crypto import OSKeyringProvider
from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.domain.frames import RedactedRecord
from local_recall.domain.privacy import PrivacyClass, ProviderLocation
from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    ProviderCapabilities,
)
from local_recall.index.semantic import EncryptedSemanticIndex, IndexDocument
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.retention.gc import GarbageCollector
from local_recall.storage import SQLiteEncryptedStorage
from local_recall.timeline.activity_rebuild import SurvivingRecordActivityReconciler
from tests.unit.retention.test_planner import make_envelope, make_record


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


class EchoGenerator:
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
        source_id = re.findall(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            request.prompt,
        )[0]
        return GenerationResponse(
            provider_id="local-generation",
            model_id="summary-v1",
            text=json.dumps(
                {"evidence": [{"source_id": source_id, "excerpt": request.context[0]}]}
            ),
        )


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _document(record: RedactedRecord) -> IndexDocument:
    return IndexDocument(
        record_id=record.record_id,
        captured_at=record.frame.captured_at,
        text="gc probe",
        approved_metadata=(),
        privacy_class=PrivacyClass.REDACTED_CONTENT,
    )


def _wire(tmp_path: Path, records: list[RedactedRecord]):
    storage = SQLiteEncryptedStorage(
        tmp_path / "storage", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    key_provider = OSKeyringProvider(MemoryKeyringBackend())
    for record in records:
        asyncio.run(storage.put(make_envelope(record)))
    activity_store = EncryptedActivityStore(tmp_path / "activity", key_provider)
    index = EncryptedSemanticIndex(tmp_path / "semantic", key_provider)
    if records:
        asyncio.run(index.rebuild(tuple(_document(r) for r in records), Embeddings()))
    reconciler = activity_reconcile.ActivityReconciler(
        feature_extractor=ActivityFeatureExtractor(Embeddings()),
        segmenter=ActivitySegmenter(
            ActivityClusteringPolicy(
                max_gap_seconds=600.0,
                strong_gap_seconds=120.0,
                minimum_continuity_score=0.5,
                minimum_semantic_similarity=0.5,
            )
        ),
        summarizer=ActivitySummarizer(EchoGenerator()),
        store=activity_store,
    )
    asyncio.run(reconciler.reconcile(tuple(records)))
    rebuild = SurvivingRecordActivityReconciler(
        storage=storage,
        encryption=_Decryptor({r.record_id: r for r in records}),
        reconciler=reconciler,
        store=activity_store,
    )
    sink = MemoryAuditSink()
    collector = GarbageCollector(
        storage=storage,
        semantic_index=index,
        activity_store=activity_store,
        activity_rebuild=rebuild,
        audit=AuditRecorder(sink),
    )
    return collector, storage, index, activity_store, sink


class _Decryptor:
    provider_id = "gc-decryptor"

    def __init__(self, records: dict[UUID, RedactedRecord]) -> None:
        self._records = records

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        return self._records[request.envelope.record_id]

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        raise AssertionError("gc must never encrypt")


def test_gc_prunes_stale_index_entries_and_rebuilds_activity(tmp_path: Path) -> None:
    victim = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    survivor = make_record(2, captured_at=datetime(2026, 8, 1, 10, 1, tzinfo=UTC))
    collector, storage, index, activity_store, sink = _wire(tmp_path, [victim, survivor])

    from local_recall.ports.storage import DeleteRequest

    asyncio.run(storage.delete(DeleteRequest(victim.record_id, "gc-test")))

    result = asyncio.run(collector.collect())

    assert result.pruned_index_entries >= 1
    assert victim.record_id not in asyncio.run(index.record_ids())
    assert survivor.record_id in asyncio.run(index.record_ids())
    snapshot = asyncio.run(activity_store.load())
    assert snapshot is not None
    members = {rid for e in snapshot.entries for rid in e.cluster.source_record_ids}
    assert victim.record_id not in members
    assert survivor.record_id in members
    assert [e for e in sink.events if e.action is AuditAction.GARBAGE_COLLECTION]


def test_gc_is_idempotent(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    collector, _storage, index, _activity_store, _sink = _wire(tmp_path, [record])

    first = asyncio.run(collector.collect())
    second = asyncio.run(collector.collect())

    assert first.pruned_index_entries == 0
    assert second.pruned_index_entries == 0
    assert asyncio.run(index.record_ids()) == (record.record_id,)


def test_gc_noop_when_everything_consistent(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    collector, _storage, _index, _activity_store, _sink = _wire(tmp_path, [record])

    result = asyncio.run(collector.collect())

    assert result.pruned_index_entries == 0
    assert result.rebuilt_activity is False
