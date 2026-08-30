"""Synthetic-desktop end-to-end harness assembling the real Local Recall stack."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pykka

from local_recall.answering.models import AnswerMode, CitedAnswer
from local_recall.answering.service import AnsweringService
from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.config import (
    CaptureSettings,
    ConfigurationSnapshot,
    CredentialReference,
    EncryptionSettings,
    LocalRecallConfig,
    MetadataSettings,
    PrivacyProfile,
    StorageSettings,
)
from local_recall.crypto.codec import decode_encrypted_stage
from local_recall.crypto.envelope import EnvelopeCipher
from local_recall.crypto.keyring import OSKeyringProvider
from local_recall.crypto.processor import EnvelopeEncryptionStageProcessor
from local_recall.crypto.registry import KeyProviderRegistry
from local_recall.domain.capture import (
    ApprovedCaptureRequest,
    CaptureDecision,
    CaptureIntent,
)
from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.domain.frames import (
    CaptureProvenance,
    CaptureRegion,
    OCRBlock,
    OCRResult,
    PixelFormat,
    RawFrame,
    RedactedRecord,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.privacy import PrivacyClass
from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
    GenerationRequest,
    GenerationResponse,
    ModelCapability,
    ProviderCapabilities,
    ProviderLocation,
)
from local_recall.domain.redaction import PixelRegion
from local_recall.index.semantic import EncryptedSemanticIndex, IndexDocument
from local_recall.lifecycle import (
    CaptureGate,
    LifecycleActor,
    LifecycleAuditEvent,
    LifecycleCommandResult,
    LifecyclePreflightRequest,
    LifecyclePreflightResult,
    StartCapture,
    StopCapture,
)
from local_recall.pipeline.cancellation import PipelineCancellationToken
from local_recall.pipeline.models import RawStageItem
from local_recall.ports.ocr import OCRRequest
from local_recall.ports.redaction import RedactionRequest
from local_recall.ports.storage import StorageUsageReport
from local_recall.redaction.codec import (
    decode_redacted_stage,
    encode_analyzed_stage,
    encode_raw_frame,
    encode_redacted_stage,
)
from local_recall.redaction.policy import DeterministicRedactionPolicy
from local_recall.retrieval.service import (
    RetrievalPolicyDecision,
    RetrievalQuery,
    RetrievalService,
    SemanticCandidate,
)
from local_recall.routing import RoutingMode, RoutingPolicy
from local_recall.storage import SQLiteEncryptedStorage

PROVENANCE_SOURCE = "synthetic-desktop"
CONFIGURATION_REVISION = "e2e-config-v1"
ADAPTER_REVISION = "e2e-desktop-v1"
POLICY_REVISION = "e2e-policy-v1"


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


class AdvanceClock:
    """Deterministic clock the scenario advances explicitly."""

    def __init__(self, start: datetime, *, step_seconds: float = 60.0) -> None:
        self._value = start
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> datetime:
        return self._value

    def advance(self) -> datetime:
        self._value = self._value + self._step
        return self._value

    def jump_to(self, value: datetime) -> None:
        self._value = value


@dataclass(frozen=True, slots=True)
class DesktopWindow:
    application: str
    title: str
    workspace: str = "ws-1"


@dataclass
class SyntheticDesktop:
    """Deterministic fake desktop: metadata and OCR text, never a real screen."""

    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    windows: list[DesktopWindow] = field(
        default_factory=lambda: [DesktopWindow("emacs", "project-notes")]
    )
    focused: int = 0
    screen_secrets: tuple[str, ...] = ()

    def focused_window(self) -> DesktopWindow:
        return self.windows[max(0, min(self.focused, len(self.windows) - 1))]

    def metadata(self, observed_at: datetime) -> ContextMetadata:
        window = self.focused_window()
        provenance = (
            MetadataProvenance(
                source_id=PROVENANCE_SOURCE,
                observed_at=observed_at,
                confidence=SourceConfidence(1.0),
                adapter_revision=ADAPTER_REVISION,
            ),
        )
        return ContextMetadata(
            observed_at=observed_at,
            fields=(
                ContextField("application", window.application, provenance),
                ContextField("window.title", window.title, provenance),
                ContextField("workspace", window.workspace, provenance),
            ),
        )

    def ocr_lines(self) -> tuple[str, ...]:
        window = self.focused_window()
        lines = [f"{window.application} {window.title}"]
        lines.extend(f"token: {secret}" for secret in self.screen_secrets)
        return tuple(lines)


@dataclass
class SyntheticCaptureBackend:
    """CaptureBackend port over the synthetic desktop."""

    desktop: SyntheticDesktop
    ocr_texts: dict[UUID, tuple[str, ...]] = field(default_factory=dict[UUID, tuple[str, ...]])
    captures: int = 0
    backend_id = "synthetic-capture"

    async def capture(self, request: ApprovedCaptureRequest) -> RawFrame:
        self.captures += 1
        observed_at = self.desktop.clock()
        region = CaptureRegion(0, 0, 8, 2)
        frame = RawFrame(
            frame_id=uuid4(),
            generation=request.intent.generation,
            captured_at=observed_at,
            width=8,
            height=2,
            stride=24,
            pixel_format=PixelFormat.RGB8,
            pixels=bytes(48),
            metadata=request.metadata,
            capture_provenance=CaptureProvenance(
                backend_id=self.backend_id,
                backend_revision="e2e-synthetic-v1",
                root_region=region,
                region=region,
                monitors=(),
            ),
        )
        self.ocr_texts[frame.frame_id] = self.desktop.ocr_lines()
        return frame


@dataclass
class SyntheticOCR:
    """OCRProvider that reports the deterministic lines registered per frame."""

    texts: dict[UUID, tuple[str, ...]]
    provider_id = "synthetic-ocr"

    async def recognize(self, request: OCRRequest) -> OCRResult:
        lines = self.texts.get(request.frame.frame_id, ())
        blocks = tuple(
            OCRBlock(
                block_id=uuid4(),
                frame_id=request.frame.frame_id,
                text=line,
                confidence=SourceConfidence(0.99),
                region=PixelRegion(0, 0, 8, 1),
            )
            for line in lines
        )
        return OCRResult(request.frame.frame_id, blocks)


class HashEmbeddingProvider:
    """Topical-permissive synthetic embedding model (shared semantic component).

    The leading constant dimension makes every text share a baseline similarity
    so the real cosine math in the index stays above the retrieval floor; the
    hashed components keep ordering deterministic per text.
    """

    model_id = "e2e-embedding-v1"

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="e2e-embeddings",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.EMBEDDING}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=64 * 1024,
            supports_vision=False,
        )

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        vectors = tuple(self._vector(text) for text in request.inputs)
        return EmbeddingResponse("e2e-embeddings", self.model_id, vectors)

    def _vector(self, text: str) -> tuple[float, ...]:
        digest = abs(hash(text)) % (2**32)
        return (
            1.0,
            float(digest % 97) / 97.0,
            float((digest >> 7) % 89) / 89.0,
            float((digest >> 13) % 83) / 83.0,
        )


class AnswerGenerationProvider:
    """Local generation provider returning a cited claim for evidence checks."""

    def __init__(self) -> None:
        self.requests: list[GenerationRequest] = []

    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="e2e-generation",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=64 * 1024,
            supports_vision=False,
            supports_structured_output=True,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        self.requests.append(request)
        labelled = request.context[0]
        excerpt = labelled.split(": ", 1)[1] if ": " in labelled else labelled
        claim = excerpt.strip()
        return GenerationResponse(
            text=(
                '{"claims":[{"kind":"observed","text":'
                + json.dumps(claim)
                + ',"evidence_ids":["E1"]}]}'
            ),
            provider_id="e2e-generation",
            model_id="e2e-model-v1",
        )


class E2EDecryptor:
    provider_id = "e2e-decryptor"

    def __init__(self, cipher: EnvelopeCipher, key_provider: OSKeyringProvider) -> None:
        self._cipher = cipher
        self._key_provider = key_provider

    async def decrypt(self, request: object) -> RedactedRecord:
        from local_recall.pipeline.models import RedactedStageItem
        from local_recall.ports.encryption import DecryptionRequest

        assert isinstance(request, DecryptionRequest)
        envelope = request.envelope
        plain_frames = await self._cipher.decrypt_frames(envelope, self._key_provider)
        rebuilt = RedactedStageItem(
            record_id=envelope.record_id,
            generation=envelope.generation,
            configuration_revision=envelope.configuration_revision,
            deadline_monotonic_ns=1,
            frames=tuple(bytes(f) for f in plain_frames),
        )
        return decode_redacted_stage(rebuilt)

    async def encrypt(self, request: object) -> EncryptedRecordEnvelope:
        raise AssertionError("e2e retrieval must never encrypt")


class E2EPolicy:
    async def authorize_query(self, query: RetrievalQuery) -> RetrievalPolicyDecision:
        del query
        return RetrievalPolicyDecision(True, False, "query-policy-v1", "allowed")

    async def authorize_record(
        self, query: RetrievalQuery, record: RedactedRecord
    ) -> RetrievalPolicyDecision:
        del query, record
        return RetrievalPolicyDecision(True, False, "query-policy-v1", "allowed")


class E2ESemanticSearch:
    def __init__(self, index: EncryptedSemanticIndex, embeddings: HashEmbeddingProvider) -> None:
        self._index = index
        self._embeddings = embeddings

    async def search(
        self,
        text: str,
        *,
        start_at: datetime,
        end_at: datetime,
        limit: int,
    ) -> tuple[SemanticCandidate, ...]:
        from local_recall.index.semantic import SemanticQuery

        hits = await self._index.search(
            SemanticQuery(text=text, start_at=start_at, end_at=end_at, limit=limit),
            self._embeddings,
        )
        return tuple(SemanticCandidate(hit.record_id, hit.captured_at, hit.score) for hit in hits)


class LifecycleSupport:
    def snapshot(self) -> ConfigurationSnapshot:
        return ConfigurationSnapshot(
            configuration=LocalRecallConfig(
                profile=PrivacyProfile.LOCAL_ONLY,
                capture=CaptureSettings(enabled=True),
                metadata=MetadataSettings(enabled_sources=(PROVENANCE_SOURCE,)),
                encryption=EncryptionSettings(
                    provider_id="os-keyring",
                    key_reference=CredentialReference(
                        provider_id="os-keyring",
                        reference="e2e-record-key",
                    ),
                ),
                storage=StorageSettings(
                    backend_id="e2e-storage",
                    root_directory="/tmp/local-recall-e2e-storage",
                ),
            ),
            revision=CONFIGURATION_REVISION,
            source="synthetic",
            loaded_at=datetime.now(UTC),
        )


class E2EPreflight:
    def check(self, request: LifecyclePreflightRequest) -> LifecyclePreflightResult:
        del request
        return LifecyclePreflightResult.success()


class E2ECoordinator:
    def cancel_queued(self, generation: CaptureGeneration) -> None:
        del generation

    def cancel_in_flight(self, generation: CaptureGeneration) -> None:
        del generation

    def wait_for_quiescence(self, generation: CaptureGeneration, timeout_seconds: float) -> bool:
        del generation, timeout_seconds
        return True

    def clear_volatile_buffers(self, generation: CaptureGeneration | None) -> None:
        del generation


class E2EAuditSink:
    def __init__(self) -> None:
        self.events: list[LifecycleAuditEvent | AuditEvent] = []

    def emit(self, event: LifecycleAuditEvent | AuditEvent) -> None:
        self.events.append(event)


class HarnessClock:
    """Clock port binding the deterministic scenario clock into sync stages."""

    def __init__(self, clock: AdvanceClock) -> None:
        self._clock = clock

    def now(self) -> datetime:
        return self._clock.now()

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()


@dataclass
class LocalRecallSystem:
    """Full Local Recall stack over a synthetic desktop."""

    root: Path
    clock: AdvanceClock
    desktop: SyntheticDesktop
    key_backend: MemoryKeyringBackend | None = None

    def __post_init__(self) -> None:
        self.ocr_texts: dict[UUID, tuple[str, ...]] = {}
        self.capture_backend = SyntheticCaptureBackend(self.desktop, self.ocr_texts)
        self.ocr = SyntheticOCR(self.ocr_texts)
        self.key_backend = self.key_backend or MemoryKeyringBackend()
        self.key_provider = OSKeyringProvider(self.key_backend)
        self.cipher = EnvelopeCipher()
        self.registry = KeyProviderRegistry((self.key_provider,))
        self.encryption_stage = EnvelopeEncryptionStageProcessor(
            self.registry,
            primary_provider_id="os-keyring",
            cipher=self.cipher,
            clock=HarnessClock(self.clock),
        )
        self.storage = SQLiteEncryptedStorage(
            self.root / "storage", quota_bytes=1_000_000_000, max_blob_bytes=1_000_000
        )
        self.policy = DeterministicRedactionPolicy(now=self.clock.now)
        self.embeddings = HashEmbeddingProvider()
        self.index = EncryptedSemanticIndex(self.root / "index", self.key_provider)
        self.audit_sink = E2EAuditSink()
        self.audit = AuditRecorder(self.audit_sink)
        self.generation_provider = AnswerGenerationProvider()
        self.gate = CaptureGate()
        self.actor_ref = LifecycleActor.start(
            gate=self.gate,
            configuration_source=LifecycleSupport(),
            preflight=E2EPreflight(),
            work_coordinator=E2ECoordinator(),
            audit_sink=self.audit_sink,
            stop_timeout_seconds=1,
        )
        self.records: list[RedactedRecord] = []
        self.last_raw_frame: RawFrame | None = None
        self.index_documents: list[IndexDocument] = []
        self._waiter = threading.Event()

    def start(self) -> None:
        result = cast(LifecycleCommandResult, self.actor_ref.ask(StartCapture(), timeout=2))
        assert result.snapshot.state.value in {"starting", "recording"}

    def wait_recording(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        snapshot = self.gate.snapshot()
        while snapshot.state.value != "recording" and time.monotonic() < deadline:
            self._waiter.wait(0.005)
            snapshot = self.gate.snapshot()
        assert snapshot.state.value == "recording"

    def stop(self) -> None:
        cast(LifecycleCommandResult, self.actor_ref.ask(StopCapture(), timeout=2))

    async def capture_once(self) -> RedactedRecord:
        """One approved capture through capture -> redaction -> encrypt -> persist -> index."""
        snapshot = self.gate.snapshot()
        generation = snapshot.generation
        assert generation is not None
        observed_at = self.clock.now()
        intent = CaptureIntent(
            job_id=uuid4(),
            generation=generation,
            requested_at=observed_at,
            deadline_monotonic_ns=time.monotonic_ns() + 5_000_000_000,
            configuration_revision=CONFIGURATION_REVISION,
        )
        decision = CaptureDecision.allow(
            policy_revision=POLICY_REVISION,
            allowed_metadata_fields=frozenset({"application", "window.title", "workspace"}),
        )
        request = ApprovedCaptureRequest.from_decision(
            intent=intent, metadata=self.desktop.metadata(observed_at), decision=decision
        )
        frame = await self.capture_backend.capture(request)
        self.last_raw_frame = frame
        ocr = await self.ocr.recognize(OCRRequest(frame=frame, language_hints=("en",)))
        record = await self.policy.redact(
            RedactionRequest(frame=frame, ocr=ocr, policy_revision=self.policy.revision)
        )
        analyzed = encode_analyzed_stage(
            raw_stage_item(frame, generation, intent.deadline_monotonic_ns),
            frame,
            ocr,
        )
        redacted_item = encode_redacted_stage(analyzed, record)
        encrypted_item = await asyncio.to_thread(
            self.encryption_stage.process,
            redacted_item,
            PipelineCancellationToken(generation=generation, _local_event=threading.Event()),
        )
        await self.storage.put(decode_encrypted_stage(encrypted_item))
        document = IndexDocument(
            record_id=record.record_id,
            captured_at=record.frame.captured_at,
            text=" ".join(record.frame.ocr_text),
            approved_metadata=(str(record.frame.metadata.get("application") or "unknown"),),
            privacy_class=PrivacyClass.REDACTED_CONTENT,
        )
        if self.index_documents:
            await self.index.add((document,), self.embeddings)
        else:
            await self.index.rebuild((document,), self.embeddings)
        self.index_documents.append(document)
        self.records.append(record)
        return record

    def usage(self) -> StorageUsageReport:
        return asyncio.run(self.storage.stats())

    def indexed_count(self) -> int:
        return len(asyncio.run(self.index.record_ids()))

    async def ask(self, question: str, *, now: datetime) -> CitedAnswer:
        retrieval = RetrievalService(
            storage=self.storage,
            encryption=E2EDecryptor(self.cipher, self.key_provider),
            policy=E2EPolicy(),
            semantic_search=E2ESemanticSearch(self.index, self.embeddings),
        )
        service = AnsweringService(
            retrieval=retrieval,
            routing=RoutingPolicy(RoutingMode.LOCAL_ONLY),
            local_providers=(self.generation_provider,),
        )
        return await service.answer(question, now=now, timezone="UTC", mode=AnswerMode.TIMELINE)

    def shutdown(self) -> None:
        pykka.ActorRegistry.stop_all(block=True, timeout=2)


def raw_stage_item(
    frame: RawFrame, generation: CaptureGeneration, deadline_monotonic_ns: int
) -> RawStageItem:
    return RawStageItem(
        record_id=frame.frame_id,
        generation=generation,
        configuration_revision=CONFIGURATION_REVISION,
        deadline_monotonic_ns=deadline_monotonic_ns,
        frames=tuple(bytearray(part) for part in encode_raw_frame(frame)),
    )
