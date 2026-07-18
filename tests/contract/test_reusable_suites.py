from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.domain.capture import (
    ApprovedCaptureRequest,
    CaptureDecision,
    CaptureIntent,
    MetadataRequest,
)
from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle, StoredRecordRef
from local_recall.domain.frames import PixelFormat, RawFrame
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
from local_recall.ports.capture import CaptureBackend
from local_recall.ports.metadata import MetadataSource
from local_recall.ports.providers import EmbeddingProvider, GenerationProvider
from local_recall.ports.storage import DeleteRequest, DeleteResult, StorageBackend

from .suites import (
    CaptureBackendContract,
    EmbeddingProviderContract,
    GenerationProviderContract,
    MetadataSourceContract,
    StorageBackendContract,
)


def metadata() -> ContextMetadata:
    return ContextMetadata(observed_at=datetime.now(UTC), fields=())


def approved_request() -> ApprovedCaptureRequest:
    intent = CaptureIntent(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        requested_at=datetime.now(UTC),
        deadline_monotonic_ns=1,
        configuration_revision="config-v1",
    )
    decision = CaptureDecision.allow(
        policy_revision="policy-v1",
        allowed_metadata_fields=frozenset(),
    )
    return ApprovedCaptureRequest.from_decision(
        intent=intent,
        metadata=metadata(),
        decision=decision,
    )


class SyntheticCaptureBackend:
    backend_id = "synthetic-capture"

    async def capture(self, request: ApprovedCaptureRequest) -> RawFrame:
        return RawFrame(
            frame_id=uuid4(),
            generation=request.intent.generation,
            captured_at=datetime.now(UTC),
            width=1,
            height=1,
            stride=4,
            pixel_format=PixelFormat.RGBA8,
            pixels=b"RGBA",
            metadata=request.metadata,
        )


class SyntheticMetadataSource:
    source_id = "synthetic-metadata"

    async def collect(self, request: MetadataRequest) -> ContextMetadata:
        assert request.generation == CaptureGeneration(1)
        return metadata()


class SyntheticEmbeddingProvider:
    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="synthetic-embedding",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.EMBEDDING}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=1024,
            supports_vision=False,
        )

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        return EmbeddingResponse(
            provider_id="synthetic-embedding",
            model_id="fixture",
            vectors=tuple((1.0, 0.0) for _ in request.inputs),
        )


class SyntheticGenerationProvider:
    async def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="synthetic-generation",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset({ModelCapability.GENERATION}),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=1024,
            supports_vision=False,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        assert request.privacy_class is PrivacyClass.REDACTED_CONTENT
        return GenerationResponse(
            text="synthetic answer",
            provider_id="synthetic-generation",
            model_id="fixture",
        )


class SyntheticStorageBackend:
    backend_id = "synthetic-storage"

    def __init__(self) -> None:
        self._records: dict[UUID, EncryptedRecordEnvelope] = {}

    async def put(self, envelope: EncryptedRecordEnvelope) -> StoredRecordRef:
        self._records[envelope.record_id] = envelope
        return StoredRecordRef(
            record_id=envelope.record_id,
            storage_id=f"record:{envelope.record_id}",
            envelope_schema_version=envelope.schema_version,
        )

    async def get(self, record_id: UUID) -> EncryptedRecordEnvelope | None:
        return self._records.get(record_id)

    async def delete(self, request: DeleteRequest) -> DeleteResult:
        removed = self._records.pop(request.record_id, None)
        return DeleteResult(
            record_id=request.record_id,
            deleted=removed is not None,
            cryptographic_material_destroyed=False,
        )


def encrypted_envelope() -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=uuid4(),
        generation=CaptureGeneration(1),
        configuration_revision="config-v1",
        schema_version=1,
        algorithm="synthetic-aead",
        key=KeyHandle(key_id="key-1", provider_id="synthetic", version=1),
        plaintext_frame_sizes=(8,),
        wrapped_data_key=b"wrapped",
        nonce=b"nonce",
        ciphertext=b"ciphertext",
        associated_data_digest=b"digest",
        created_at=datetime.now(UTC),
    )


class TestSyntheticCaptureBackend(CaptureBackendContract):
    def make_capture_backend(self) -> CaptureBackend:
        return SyntheticCaptureBackend()

    def make_approved_request(self) -> ApprovedCaptureRequest:
        return approved_request()


class TestSyntheticMetadataSource(MetadataSourceContract):
    def make_metadata_source(self) -> MetadataSource:
        return SyntheticMetadataSource()

    def make_metadata_request(self) -> MetadataRequest:
        return MetadataRequest(
            job_id=uuid4(),
            generation=CaptureGeneration(1),
            deadline_monotonic_ns=1,
        )


class TestSyntheticEmbeddingProvider(EmbeddingProviderContract):
    def make_embedding_provider(self) -> EmbeddingProvider:
        return SyntheticEmbeddingProvider()

    def make_embedding_request(self) -> EmbeddingRequest:
        return EmbeddingRequest(
            inputs=("synthetic input",),
            privacy_class=PrivacyClass.REDACTED_CONTENT,
        )


class TestSyntheticGenerationProvider(GenerationProviderContract):
    def make_generation_provider(self) -> GenerationProvider:
        return SyntheticGenerationProvider()

    def make_generation_request(self) -> GenerationRequest:
        return GenerationRequest(
            prompt="synthetic prompt",
            context=("synthetic context",),
            privacy_class=PrivacyClass.REDACTED_CONTENT,
            max_output_tokens=32,
        )


class TestSyntheticStorageBackend(StorageBackendContract):
    def make_storage_backend(self) -> StorageBackend:
        return SyntheticStorageBackend()

    def make_envelope(self) -> EncryptedRecordEnvelope:
        return encrypted_envelope()
