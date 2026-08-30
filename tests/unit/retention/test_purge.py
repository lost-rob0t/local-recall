from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from local_recall.activity import reconcile as activity_reconcile
from local_recall.activity.clustering import ActivityClusteringPolicy, ActivitySegmenter
from local_recall.activity.features import ActivityFeatureExtractor
from local_recall.activity.store import EncryptedActivityStore
from local_recall.activity.summaries import ActivitySummarizer
from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.models import AuditAction
from local_recall.crypto import OSKeyringProvider
from local_recall.domain import KeyPurpose, KeyRequest
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
from local_recall.index.semantic import EncryptedSemanticIndex, IndexDocument, IndexFailure
from local_recall.retention.purge import PurgeAllEngine
from local_recall.storage import SQLiteEncryptedStorage
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


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _document(record: RedactedRecord) -> IndexDocument:
    return IndexDocument(
        record_id=record.record_id,
        captured_at=record.frame.captured_at,
        text="retention purge probe",
        approved_metadata=(),
        privacy_class=PrivacyClass.REDACTED_CONTENT,
    )


def _wire(tmp_path: Path, records: list[RedactedRecord]):
    storage = SQLiteEncryptedStorage(
        tmp_path / "storage", quota_bytes=100_000_000, max_blob_bytes=1_000_000
    )
    key_provider = OSKeyringProvider(MemoryKeyringBackend())
    asyncio.run(key_provider.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True)))
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
    sink = MemoryAuditSink()
    audit = AuditRecorder(sink)
    engine = PurgeAllEngine(
        storage=storage,
        activity_store=activity_store,
        semantic_index=index,
        key_provider=key_provider,
        audit=audit,
    )
    return engine, storage, index, activity_store, reconciler, sink


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
        import json
        import re

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


def test_purge_all_removes_every_record_and_invalidates_derived_state(tmp_path: Path) -> None:
    first = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    second = make_record(2, captured_at=datetime(2026, 8, 2, 10, 0, tzinfo=UTC))
    engine, storage, index, activity_store, reconciler, sink = _wire(tmp_path, [first, second])
    asyncio.run(reconciler.reconcile((first, second)))
    snapshot = asyncio.run(activity_store.load())
    assert snapshot is not None and len(snapshot.entries) >= 1

    result = asyncio.run(engine.purge())

    assert result.deleted_count == 2
    assert asyncio.run(storage.stats()).ready_records == 0
    assert asyncio.run(storage.get(first.record_id)) is None
    with pytest.raises(IndexFailure, match="not initialized"):
        asyncio.run(index.manifest())
    purged_snapshot = asyncio.run(activity_store.load())
    assert purged_snapshot is not None and purged_snapshot.entries == ()
    purges = [e for e in sink.events if e.action is AuditAction.PURGE_ALL]
    assert len(purges) == 1
    assert purges[0].attributes["count"] == 2
    assert purges[0].attributes["success"] is True


def test_purge_all_destroys_active_record_key_material(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    engine, _storage, _index, _activity_store, _reconciler, _sink = _wire(tmp_path, [record])
    handle = asyncio.run(engine.active_record_key())

    result = asyncio.run(engine.purge())

    assert result.deleted_count == 1
    assert handle is not None
    health = asyncio.run(_key_health(engine))
    assert health.ready is False


async def _key_health(engine: PurgeAllEngine):

    return await engine.key_provider.health(KeyRequest(KeyPurpose.RECORD))


def test_purge_all_dry_run_reports_without_touching(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    engine, storage, _index, _activity_store, _reconciler, sink = _wire(tmp_path, [record])

    result = asyncio.run(engine.purge(dry_run=True))

    assert result.deleted_count == 0
    assert result.planned_count == 1
    assert asyncio.run(storage.get(record.record_id)) is not None
    assert asyncio.run(storage.stats()).ready_records == 1
    assert [e for e in sink.events if e.action is AuditAction.PURGE_ALL] == []


def test_purge_all_is_idempotent(tmp_path: Path) -> None:
    record = make_record(1, captured_at=datetime(2026, 8, 1, 10, 0, tzinfo=UTC))
    engine, _storage, _index, _activity_store, _reconciler, _sink = _wire(tmp_path, [record])

    first = asyncio.run(engine.purge())
    second = asyncio.run(engine.purge())

    assert first.deleted_count == 1
    assert second.deleted_count == 0
