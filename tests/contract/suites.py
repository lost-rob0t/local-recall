from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

from local_recall.domain.capture import ApprovedCaptureRequest, MetadataRequest
from local_recall.domain.crypto import EncryptedRecordEnvelope, StoredRecordRef
from local_recall.domain.frames import RawFrame
from local_recall.domain.metadata import ContextMetadata
from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
    GenerationRequest,
    GenerationResponse,
)
from local_recall.ports.capture import CaptureBackend
from local_recall.ports.metadata import MetadataSource
from local_recall.ports.providers import EmbeddingProvider, GenerationProvider
from local_recall.ports.storage import StorageBackend


class CaptureBackendContract(ABC):
    @abstractmethod
    def make_capture_backend(self) -> CaptureBackend: ...

    @abstractmethod
    def make_approved_request(self) -> ApprovedCaptureRequest: ...

    def test_capture_returns_raw_frame(self) -> None:
        result = asyncio.run(self.make_capture_backend().capture(self.make_approved_request()))
        assert isinstance(result, RawFrame)


class MetadataSourceContract(ABC):
    @abstractmethod
    def make_metadata_source(self) -> MetadataSource: ...

    @abstractmethod
    def make_metadata_request(self) -> MetadataRequest: ...

    def test_collect_returns_context_metadata(self) -> None:
        result = asyncio.run(self.make_metadata_source().collect(self.make_metadata_request()))
        assert isinstance(result, ContextMetadata)


class EmbeddingProviderContract(ABC):
    @abstractmethod
    def make_embedding_provider(self) -> EmbeddingProvider: ...

    @abstractmethod
    def make_embedding_request(self) -> EmbeddingRequest: ...

    def test_embed_returns_typed_response(self) -> None:
        result = asyncio.run(self.make_embedding_provider().embed(self.make_embedding_request()))
        assert isinstance(result, EmbeddingResponse)


class GenerationProviderContract(ABC):
    @abstractmethod
    def make_generation_provider(self) -> GenerationProvider: ...

    @abstractmethod
    def make_generation_request(self) -> GenerationRequest: ...

    def test_generate_returns_typed_response(self) -> None:
        result = asyncio.run(
            self.make_generation_provider().generate(self.make_generation_request())
        )
        assert isinstance(result, GenerationResponse)


class StorageBackendContract(ABC):
    @abstractmethod
    def make_storage_backend(self) -> StorageBackend: ...

    @abstractmethod
    def make_envelope(self) -> EncryptedRecordEnvelope: ...

    def test_encrypted_envelope_round_trip(self) -> None:
        backend = self.make_storage_backend()
        envelope = self.make_envelope()

        stored = asyncio.run(backend.put(envelope))
        loaded = asyncio.run(backend.get(envelope.record_id))

        assert isinstance(stored, StoredRecordRef)
        assert loaded == envelope
