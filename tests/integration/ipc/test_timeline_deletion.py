from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from local_recall.timeline.ipc import TimelineDeletionHandler

from local_recall import ipc, ipc_transport
from local_recall.activity import reconcile as activity_reconcile
from local_recall.activity.clustering import ActivityClusteringPolicy, ActivitySegmenter
from local_recall.activity.features import ActivityFeatureExtractor
from local_recall.activity.store import EncryptedActivityStore
from local_recall.activity.summaries import ActivitySummarizer
from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.adapters import IpcAuditAdapter
from local_recall.audit.models import AuditAction
from local_recall.cli_contract import CliCommand, CliOutcome
from local_recall.crypto import OSKeyringProvider
from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
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
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    ProviderCapabilities,
)
from local_recall.index.semantic import EncryptedSemanticIndex
from local_recall.storage import SQLiteEncryptedStorage
from local_recall.timeline.deletion import DeletionCoordinator, DeletionJournal
from local_recall.timeline.inspection import TimelineInspector
from local_recall.timeline.scope import DeletionScopeResolver


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


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


_BASE = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)


def _record(
    index: int,
    *,
    captured_at: datetime,
    text: str,
    application: str = "emacs",
) -> RedactedRecord:
    provenance = MetadataProvenance(
        source_id="synthetic-metadata",
        observed_at=captured_at,
        confidence=SourceConfidence(0.9),
        adapter_revision="integration-v1",
    )
    metadata = ContextMetadata(
        observed_at=captured_at,
        fields=(ContextField("application", application, (provenance,)),),
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


class Decryptor:
    provider_id = "ipc-integration-decryptor"

    def __init__(self, records: dict) -> None:
        self._records = records

    async def decrypt(self, request) -> RedactedRecord:
        return self._records[request.envelope.record_id]

    async def encrypt(self, request):
        raise AssertionError("IPC handler must never encrypt")


class SeedStorage:
    """Direct envelope storage used only to seed the real SQLite backend."""

    def __init__(self, backend: SQLiteEncryptedStorage) -> None:
        self._backend = backend

    def seed(self, *records: RedactedRecord) -> None:
        for record in records:
            import asyncio

            asyncio.run(self._backend.put(_envelope(record)))


def _wire(tmp_path: Path, *records: RedactedRecord):
    backend = SQLiteEncryptedStorage(
        tmp_path / "storage", quota_bytes=10_000_000, max_blob_bytes=1_000_000
    )
    SeedStorage(backend).seed(*records)

    key_provider = OSKeyringProvider(MemoryKeyringBackend())
    activity_root = tmp_path / "activity"
    activity_store = EncryptedActivityStore(activity_root, key_provider)
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

    index_root = tmp_path / "semantic"
    semantic_index = EncryptedSemanticIndex(index_root, key_provider)

    class SemanticOnlyIndex:
        async def remove(self, record_ids) -> object:
            return asyncio.run(_remove(record_ids))

    async def _remove(record_ids):
        return await semantic_index.remove(record_ids)

    del SemanticOnlyIndex, _remove

    class SyncRemoveAdapter:
        async def remove(self, record_ids) -> object:
            return await semantic_index.remove(record_ids)

    journal = DeletionJournal(tmp_path / "deletion")
    coordinator = DeletionCoordinator(
        journal=journal,
        storage=backend,
        semantic_index=SyncRemoveAdapter(),
        activity_reconciler=reconciler,
    )
    decryptor = Decryptor({record.record_id: record for record in records})
    inspector = TimelineInspector(
        storage=backend,
        encryption=decryptor,
        activity_store=activity_store,
    )
    resolver = DeletionScopeResolver(
        storage=backend,
        encryption=decryptor,
        activity_store=activity_store,
    )
    audit_sink = MemoryAuditSink()
    audit = AuditRecorder(audit_sink)
    handler = TimelineDeletionHandler(
        inspector=inspector,
        resolver=resolver,
        coordinator=coordinator,
        audit=audit,
    )
    return handler, audit_sink, backend, decryptor


def _paths(tmp_path: Path) -> ipc.IpcPaths:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    runtime_dir.chmod(0o700)
    return ipc.IpcPaths.from_runtime_dir(runtime_dir, expected_uid=os.getuid())


def _request(command: CliCommand, **kwargs):
    now = datetime.now(UTC)
    return CliRequest.create(
        command=command,
        now=now,
        deadline=now + timedelta(seconds=5),
        **kwargs,
    )


def test_authenticated_ipc_inspection_and_deletion_round_trip(tmp_path: Path) -> None:
    victim = _record(1, captured_at=_BASE, text="IPC-VICTIM-MARKER-77a2")
    survivor = _record(2, captured_at=_BASE + timedelta(minutes=1), text="IPC-SURVIVOR-MARKER")
    handler, audit_sink, backend, decryptor = _wire(tmp_path, victim, survivor)
    paths = _paths(tmp_path)

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
        audit=IpcAuditAdapter(AuditRecorder(MemoryAuditSink())),
    )
    server.start()
    try:
        client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())

        timeline_response = client.request(
            _request(
                CliCommand.TIMELINE,
                start=_BASE - timedelta(minutes=1),
                end=_BASE + timedelta(hours=1),
            )
        )
        assert timeline_response.outcome is CliOutcome.SUCCESS
        assert timeline_response.query_payload is not None
        assert "IPC-VICTIM-MARKER-77a2" in timeline_response.query_payload.text
        assert "IPC-SURVIVOR-MARKER" in timeline_response.query_payload.text

        preview_response = client.request(
            _request(
                CliCommand.PREVIEW_RECORD,
                record_ids=[str(victim.record_id)],
                target="text",
            )
        )
        assert preview_response.outcome is CliOutcome.SUCCESS
        assert preview_response.query_payload is not None
        assert "IPC-VICTIM-MARKER-77a2" in preview_response.query_payload.text

        deletion_response = client.request(
            _request(
                CliCommand.DELETE_RECORDS,
                record_ids=[str(victim.record_id)],
            )
        )
        assert deletion_response.outcome is CliOutcome.SUCCESS
        assert deletion_response.deletion_payload is not None
        assert deletion_response.deletion_payload.deleted_count == 1

        assert asyncio.run(backend.get(victim.record_id)) is None

        after_response = client.request(
            _request(
                CliCommand.TIMELINE,
                start=_BASE - timedelta(minutes=1),
                end=_BASE + timedelta(hours=1),
            )
        )
        assert after_response.outcome is CliOutcome.SUCCESS
        assert after_response.query_payload is not None
        assert "IPC-VICTIM-MARKER-77a2" not in after_response.query_payload.text
        assert "IPC-SURVIVOR-MARKER" in after_response.query_payload.text

        missing_preview = client.request(
            _request(
                CliCommand.PREVIEW_RECORD,
                record_ids=[str(victim.record_id)],
                target="text",
            )
        )
        assert missing_preview.outcome is CliOutcome.INVALID
        assert missing_preview.reason_code == "preview-unavailable"
    finally:
        server.close()

    deletion_events = [
        event for event in audit_sink.events if event.action is AuditAction.DELETION_REQUEST
    ]
    assert len(deletion_events) == 1
    assert deletion_events[0].attributes["success"] is True
    assert deletion_events[0].attributes["count"] == 1
    rendered = repr(deletion_events[0])
    assert "IPC-VICTIM-MARKER-77a2" not in rendered
    assert "emacs" not in rendered


def test_authenticated_ipc_survives_deletion_scope_conflicts(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="conflict-entry")
    handler, audit_sink, backend, decryptor = _wire(tmp_path, record)
    paths = _paths(tmp_path)

    server = ipc_transport.ZmqIpcServer(paths=paths, expected_uid=os.getuid(), handler=handler)
    server.start()
    try:
        client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())

        conflict = _request(
            CliCommand.DELETE_RECORDS,
            record_ids=[str(record.record_id)],
        )
        object.__setattr__(conflict, "cluster_id", "d" * 32)
        response = client.request(conflict)

        assert response.outcome is CliOutcome.INVALID
        assert response.reason_code == "ipc-rejected"
        assert asyncio.run(backend.get(record.record_id)) is not None
        assert audit_sink.events == []
    finally:
        server.close()
