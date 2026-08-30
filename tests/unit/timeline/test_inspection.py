from __future__ import annotations

import asyncio
import json
import re
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
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    ProviderCapabilities,
)
from local_recall.domain.redaction import (
    RedactionAction,
    RedactionFinding,
    RedactionKind,
    RedactionReason,
    RedactionTarget,
    TextSpan,
)
from local_recall.ports.encryption import DecryptionRequest, EncryptionRequest
from local_recall.ports.storage import (
    CatalogRecord,
    DayRangeQuery,
    DeleteRequest,
    DeleteResult,
    StorageIntegrityReport,
)
from local_recall.timeline.inspection import (
    PreviewUnavailable,
    TimelineInspector,
    TimelineQuery,
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


class FakeStorage:
    backend_id = "inspection-storage"

    def __init__(self, *records: RedactedRecord) -> None:
        self.records: dict[UUID, RedactedRecord] = {r.record_id: r for r in records}
        self.present: set[UUID] = set(self.records)
        self.deleted: list[UUID] = []

    async def list_candidates(self, request: DayRangeQuery) -> tuple[CatalogRecord, ...]:
        found: list[CatalogRecord] = []
        for record_id, record in self.records.items():
            if record_id not in self.present:
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
        if record_id not in self.present:
            return None
        return _envelope(self.records[record_id])

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        deleted = request.record_id in self.present
        self.present.discard(request.record_id)
        self.deleted.append(request.record_id)
        return DeleteResult(request.record_id, deleted, False)

    async def put(self, envelope: EncryptedRecordEnvelope):
        raise AssertionError("inspection must never encrypt")

    async def recover(self) -> StorageIntegrityReport:
        return StorageIntegrityReport()


class FakeEncryption:
    provider_id = "inspection-encryption"

    def __init__(self, records: dict[UUID, RedactedRecord]) -> None:
        self._records = records
        self.decrypted: list[UUID] = []

    async def decrypt(self, request: DecryptionRequest) -> RedactedRecord:
        record = self._records[request.envelope.record_id]
        self.decrypted.append(record.record_id)
        return record

    async def encrypt(self, request: EncryptionRequest[RedactedRecord]) -> EncryptedRecordEnvelope:
        raise AssertionError("inspection must never encrypt")


_BASE = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
_PROVENANCE = (
    MetadataProvenance(
        source_id="synthetic",
        observed_at=_BASE,
        confidence=SourceConfidence(0.9),
        adapter_revision="test-v1",
    ),
)


def _record(
    index: int,
    *,
    captured_at: datetime,
    text: str,
    application: str | None = None,
    workspace: str | None = None,
    findings: int = 0,
) -> RedactedRecord:
    fields: list[ContextField] = []
    if application is not None:
        fields.append(ContextField("application", application, _PROVENANCE))
    if workspace is not None:
        fields.append(ContextField("workspace", workspace, _PROVENANCE))
    metadata = ContextMetadata(observed_at=captured_at, fields=tuple(fields))
    finding_tuple: tuple[RedactionFinding, ...] = ()
    if findings:
        finding_tuple = (
            RedactionFinding(
                finding_id=UUID(int=index * 10),
                target=RedactionTarget.OCR_TEXT,
                kind=RedactionKind.PASSWORD,
                reason=RedactionReason.DETERMINISTIC_DETECTOR,
                action=RedactionAction.REPLACE_TEXT,
                detector_id="test-detector",
                confidence=SourceConfidence(1.0),
                text_span=TextSpan(start=0, end=1),
            ),
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
        findings=finding_tuple,
        policy_revision="redaction-policy-v7",
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
            summarizer=ActivitySummarizer(EchoGenerator()),
            store=self.store,
        )
        self.inspector = TimelineInspector(
            storage=self.storage,
            encryption=self.encryption,
            activity_store=self.store,
        )

    def seed(self, *records: RedactedRecord) -> None:
        asyncio.run(self.reconciler.reconcile(records))


def _window(*, hours: float = 2.0) -> TimelineQuery:
    return TimelineQuery(
        start_at=_BASE - timedelta(minutes=1),
        end_at=_BASE + timedelta(hours=hours),
    )


def test_timeline_lists_entries_newest_first_with_provenance(tmp_path: Path) -> None:
    first = _record(1, captured_at=_BASE, text="first-entry", application="emacs")
    second = _record(
        2,
        captured_at=_BASE + timedelta(minutes=1),
        text="second-entry",
        application="emacs",
        workspace="dev",
        findings=1,
    )
    harness = Harness(tmp_path, first, second)

    page = asyncio.run(harness.inspector.timeline(_window()))

    assert [entry.record_id for entry in page.entries] == [second.record_id, first.record_id]
    newest = page.entries[0]
    assert newest.application == "emacs"
    assert newest.workspace == "dev"
    assert newest.policy_revision == "redaction-policy-v7"
    assert newest.redaction_finding_count == 1
    assert newest.provenance[0].field_name == "application"
    assert newest.provenance[0].source_id == "synthetic"
    assert newest.provenance[0].confidence == 0.9
    assert newest.provenance[0].adapter_revision == "test-v1"
    oldest = page.entries[1]
    assert oldest.workspace is None
    assert oldest.redaction_finding_count == 0


def test_timeline_filters_by_application_and_workspace(tmp_path: Path) -> None:
    emacs = _record(1, captured_at=_BASE, text="emacs-entry", application="Emacs")
    firefox = _record(2, captured_at=_BASE + timedelta(minutes=1), text="web-entry")
    dev = _record(
        3,
        captured_at=_BASE + timedelta(minutes=2),
        text="dev-entry",
        application="emacs",
        workspace="dev",
    )
    harness = Harness(tmp_path, emacs, firefox, dev)

    application_page = asyncio.run(
        harness.inspector.timeline(
            TimelineQuery(
                start_at=_window().start_at,
                end_at=_window().end_at,
                application="emacs",
            )
        )
    )
    assert {entry.record_id for entry in application_page.entries} == {
        emacs.record_id,
        dev.record_id,
    }

    workspace_page = asyncio.run(
        harness.inspector.timeline(
            TimelineQuery(
                start_at=_window().start_at,
                end_at=_window().end_at,
                workspace="dev",
            )
        )
    )
    assert {entry.record_id for entry in workspace_page.entries} == {dev.record_id}


def test_timeline_uses_opaque_cluster_identifiers(tmp_path: Path) -> None:
    first = _record(1, captured_at=_BASE, text="cluster-entry-one")
    second = _record(2, captured_at=_BASE + timedelta(minutes=1), text="cluster-entry-two")
    harness = Harness(tmp_path, first, second)
    harness.seed(first, second)

    page = asyncio.run(harness.inspector.timeline(_window()))

    identifiers = {entry.cluster_id for entry in page.entries}
    assert len(identifiers) == 1
    cluster_id = identifiers.pop()
    assert cluster_id is not None and len(cluster_id) == 32


def test_timeline_is_bounded_and_reports_truncation(tmp_path: Path) -> None:
    records = [
        _record(index + 1, captured_at=_BASE + timedelta(minutes=index), text=f"entry-{index}")
        for index in range(5)
    ]
    harness = Harness(tmp_path, *records)

    page = asyncio.run(
        harness.inspector.timeline(
            TimelineQuery(
                start_at=_window().start_at,
                end_at=_window().end_at,
                limit=3,
            )
        )
    )

    assert len(page.entries) == 3
    assert page.truncated is True
    assert page.scanned == 5
    assert page.entries[0].captured_at > page.entries[1].captured_at


def test_timeline_requires_aware_bounded_window() -> None:
    with pytest.raises(ValueError, match="timezone"):
        TimelineQuery(
            start_at=datetime(2026, 8, 22, 10, 0),
            end_at=datetime(2026, 8, 22, 11, 0),
        )
    with pytest.raises(ValueError, match="window"):
        TimelineQuery(start_at=_BASE, end_at=_BASE)
    with pytest.raises(ValueError, match="window"):
        TimelineQuery(
            start_at=_BASE,
            end_at=_BASE + timedelta(days=400),
        )


def test_text_preview_decrypts_on_demand_without_persisting(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="PREVIEW-TEXT-MARKER-1f31")
    harness = Harness(tmp_path, record)

    preview = asyncio.run(harness.inspector.preview_text(record.record_id))

    assert preview.record_id == record.record_id
    assert preview.text == "PREVIEW-TEXT-MARKER-1f31"
    assert preview.policy_revision == "redaction-policy-v7"
    assert harness.storage.deleted == []
    for path in harness.root.rglob("*"):
        if path.is_file():
            assert b"PREVIEW-TEXT-MARKER" not in path.read_bytes()
            assert b"PREVIEW-TEXT-MARKER" not in path.read_bytes()


def test_screenshot_preview_returns_redacted_pixels_memory_only(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="screenshot-entry")
    harness = Harness(tmp_path, record)

    preview = asyncio.run(harness.inspector.preview_screenshot(record.record_id))

    assert preview.record_id == record.record_id
    assert preview.pixel_format is PixelFormat.RGB8
    assert preview.pixels == b"PIX"
    assert preview.width == 1 and preview.height == 1 and preview.stride == 3
    for path in harness.root.rglob("*"):
        if path.is_file():
            assert b"PIX" not in path.read_bytes()


def test_previews_are_memory_only_between_calls(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="no-cache-entry")
    harness = Harness(tmp_path, record)

    asyncio.run(harness.inspector.preview_text(record.record_id))
    asyncio.run(harness.inspector.preview_screenshot(record.record_id))

    harness.storage.present.clear()

    with pytest.raises(PreviewUnavailable):
        asyncio.run(harness.inspector.preview_text(record.record_id))
    with pytest.raises(PreviewUnavailable):
        asyncio.run(harness.inspector.preview_screenshot(record.record_id))


def test_preview_of_unknown_record_fails_sanitized(tmp_path: Path) -> None:
    record = _record(1, captured_at=_BASE, text="known-entry")
    harness = Harness(tmp_path, record)

    with pytest.raises(PreviewUnavailable):
        asyncio.run(harness.inspector.preview_text(UUID(int=999)))
    with pytest.raises(PreviewUnavailable):
        asyncio.run(harness.inspector.preview_screenshot(UUID(int=999)))
