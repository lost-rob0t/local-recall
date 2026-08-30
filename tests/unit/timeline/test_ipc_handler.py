from __future__ import annotations

import asyncio
import datetime as dt
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from local_recall.activity import reconcile as activity_reconcile
from local_recall.activity.clustering import ActivityClusteringPolicy, ActivitySegmenter
from local_recall.activity.features import ActivityFeatureExtractor
from local_recall.activity.store import EncryptedActivityStore
from local_recall.activity.summaries import ActivitySummarizer
from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.models import AuditAction
from local_recall.cli_contract import CliCommand, CliOutcome, CliRequest
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
from local_recall.timeline.activity_rebuild import SurvivingRecordActivityReconciler
from local_recall.timeline.deletion import DeletionCoordinator, DeletionJournal
from local_recall.timeline.inspection import TimelineInspector
from local_recall.timeline.ipc import TimelineDeletionHandler
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


class FakeStorage:
    backend_id = "handler-storage"

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

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        raise AssertionError("handler must never encrypt")

    async def recover(self) -> StorageIntegrityReport:
        return StorageIntegrityReport()


class FakeEncryption:
    provider_id = "handler-encryption"

    def __init__(self, records: dict[UUID, RedactedRecord]) -> None:
        self._records = records

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        return self._records[request.envelope.record_id]

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        raise AssertionError("handler must never encrypt")


class FakeSemanticIndex:
    def __init__(self) -> None:
        self.removed: list[tuple[UUID, ...]] = []

    async def remove(self, record_ids: tuple[UUID, ...]) -> object:
        self.removed.append(record_ids)
        return object()


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


def _record(index: int, *, captured_at: datetime, text: str) -> RedactedRecord:
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


_BASE = dt.datetime(2026, 8, 22, 10, 0, tzinfo=dt.UTC)


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class EchoGenerator:
    async def capabilities(self) -> ProviderCapabilities:
        from local_recall.domain.privacy import PrivacyClass, ProviderLocation
        from local_recall.domain.providers import ModelCapability, ProviderCapabilities

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

        from local_recall.domain.providers import GenerationResponse

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


def _request(command: CliCommand, **kwargs: object) -> CliRequest:
    now = dt.datetime.now(dt.UTC)
    return CliRequest.create(
        command=command,
        now=now,
        deadline=now + dt.timedelta(seconds=5),
        **kwargs,  # type: ignore[arg-type]
    )


class Harness:
    def __init__(self, tmp_path: Path, *records: object) -> None:
        self.storage = FakeStorage(*records)  # type: ignore[arg-type]
        self.encryption = FakeEncryption(self.storage.records)  # type: ignore[arg-type]
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
            summarizer=ActivitySummarizer(EchoGenerator()),
            store=self.store,
        )
        self.semantic_index = FakeSemanticIndex()
        self.rebuild = SurvivingRecordActivityReconciler(
            storage=self.storage,
            encryption=self.encryption,
            reconciler=self.reconciler,
            store=self.store,
        )
        self.journal = DeletionJournal(tmp_path / "deletion")
        self.coordinator = DeletionCoordinator(
            journal=self.journal,
            storage=self.storage,
            semantic_index=self.semantic_index,
            activity_reconciler=self.rebuild,
        )
        self.inspector = TimelineInspector(
            storage=self.storage,
            encryption=self.encryption,
            activity_store=self.store,
        )
        self.resolver = DeletionScopeResolver(
            storage=self.storage,
            encryption=self.encryption,
            activity_store=self.store,
        )
        self.audit_sink = MemoryAuditSink()
        self.audit = AuditRecorder(self.audit_sink)
        self.handler = TimelineDeletionHandler(
            inspector=self.inspector,
            resolver=self.resolver,
            coordinator=self.coordinator,
            audit=self.audit,
        )


def test_timeline_request_lists_entries_through_handler(tmp_path: Path) -> None:
    first = _record(1, captured_at=_BASE, text="handler-entry-one")
    second = _record(2, captured_at=_BASE + dt.timedelta(minutes=1), text="handler-entry-two")
    harness = Harness(tmp_path, first, second)

    response = harness.handler(
        _request(
            CliCommand.TIMELINE,
            start=_BASE - dt.timedelta(minutes=1),
            end=_BASE + dt.timedelta(hours=1),
        )
    )

    assert response.outcome is CliOutcome.SUCCESS
    assert response.query_payload is not None
    entries = json.loads(response.query_payload.text)
    listed_ids = {entry["record_id"] for entry in entries}
    assert listed_ids == {str(first.record_id), str(second.record_id)}
    assert "handler-entry-one" not in response.query_payload.text
    assert all(entry["redaction_finding_count"] == 0 for entry in entries)


def test_preview_request_returns_text_through_handler(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="PREVIEW-HANDLER-MARKER")
    harness = Harness(tmp_path, record)

    response = harness.handler(
        _request(
            CliCommand.PREVIEW_RECORD,
            record_ids=[str(record.record_id)],
            target="text",
        )
    )

    assert response.outcome is CliOutcome.SUCCESS
    assert response.query_payload is not None
    assert "PREVIEW-HANDLER-MARKER" in response.query_payload.text


def test_delete_request_executes_and_audits_sanitized(tmp_path: Path) -> None:
    first = _record(1, captured_at=_BASE, text="delete-handler-victim")
    second = _record(2, captured_at=_BASE + dt.timedelta(minutes=1), text="delete-handler-kept")
    harness = Harness(tmp_path, first, second)

    response = harness.handler(
        _request(
            CliCommand.DELETE_RECORDS,
            record_ids=[str(first.record_id)],
        )
    )

    assert response.outcome is CliOutcome.SUCCESS
    assert response.deletion_payload is not None
    assert response.deletion_payload.deleted_count == 1
    assert response.deletion_payload.scope_kind == "record-ids"
    assert harness.storage.deleted == [first.record_id]
    deletion_events = [
        event for event in harness.audit_sink.events if event.action is AuditAction.DELETION_REQUEST
    ]
    assert len(deletion_events) == 1
    event = deletion_events[0]
    assert event.attributes["count"] == 1
    assert event.attributes["records"] is True
    assert event.attributes["success"] is True
    assert "delete-handler-victim" not in repr(event)


def test_delete_failure_emits_failed_audit_and_sanitized_reason(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="delete-handler-failure")
    harness = Harness(tmp_path, record)
    empty_window_start = _BASE + dt.timedelta(hours=9)
    empty_window_end = _BASE + dt.timedelta(hours=10)

    response = harness.handler(
        _request(
            CliCommand.DELETE_RECORDS,
            start=empty_window_start,
            end=empty_window_end,
        )
    )

    assert response.outcome is CliOutcome.INVALID
    assert response.reason_code == "deletion-scope-invalid"
    deletion_events = [
        event for event in harness.audit_sink.events if event.action is AuditAction.DELETION_REQUEST
    ]
    assert len(deletion_events) == 1
    assert deletion_events[0].attributes["success"] is False


def test_preview_of_unavailable_record_fails_sanitized(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="unavailable-preview")
    harness = Harness(tmp_path, record)

    response = harness.handler(
        _request(
            CliCommand.PREVIEW_RECORD,
            record_ids=[str(uuid4())],
            target="image",
        )
    )

    assert response.outcome is CliOutcome.INVALID
    assert response.reason_code == "preview-unavailable"


def test_audit_failure_fails_closed_after_deletion(tmp_path: Path) -> None:
    first = _record(1, captured_at=_BASE, text="audit-failure-victim")
    harness = Harness(tmp_path, first)

    class FailingRecorder(AuditRecorder):
        def deletion_request(self, **kwargs: object) -> AuditEvent:
            from local_recall.audit.errors import AuditFailure, AuditFailureCode

            raise AuditFailure(AuditFailureCode.IO_FAILURE)

    harness.handler = TimelineDeletionHandler(
        inspector=harness.inspector,
        resolver=harness.resolver,
        coordinator=harness.coordinator,
        audit=FailingRecorder(harness.audit_sink),
    )

    response = harness.handler(
        _request(
            CliCommand.DELETE_RECORDS,
            record_ids=[str(first.record_id)],
        )
    )

    assert response.outcome is CliOutcome.INTERNAL_FAILURE
    assert response.reason_code == "audit-failed"
    assert harness.storage.deleted == [first.record_id]


def test_image_preview_is_bounded_json_without_cache(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="image-preview-entry")
    harness = Harness(tmp_path, record)

    response = harness.handler(
        _request(
            CliCommand.PREVIEW_RECORD,
            record_ids=[str(record.record_id)],
            target="image",
        )
    )

    assert response.outcome is CliOutcome.SUCCESS
    assert response.query_payload is not None
    assert '"pixel_format": "rgba8"' not in response.query_payload.text
    assert '"pixel_format":"rgb8"' in response.query_payload.text
    assert harness.storage.deleted == []


def test_handler_requires_asyncio_safe_serialization(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="concurrent-handler-entry")
    harness = Harness(tmp_path, record)

    async def exercise() -> None:
        loop = asyncio.get_running_loop()
        request = _request(
            CliCommand.TIMELINE,
            start=_BASE - dt.timedelta(minutes=1),
            end=_BASE + dt.timedelta(hours=1),
        )
        first = loop.run_in_executor(None, harness.handler, request)
        second = loop.run_in_executor(None, harness.handler, request)
        responses = await asyncio.gather(first, second)
        assert all(response.outcome is CliOutcome.SUCCESS for response in responses)

    asyncio.run(exercise())


def test_handler_rejects_unsupported_command(tmp_path: Path) -> None:
    harness = Harness(tmp_path)

    response = harness.handler(_request(CliCommand.START))

    assert response.outcome is CliOutcome.INVALID
    assert response.reason_code == "unsupported-command"
