from __future__ import annotations

from typing import Protocol, runtime_checkable

from local_recall.domain.providers import (
    EmbeddingRequest,
    EmbeddingResponse,
    GenerationRequest,
    GenerationResponse,
    ProviderCapabilities,
)


@runtime_checkable
class EmbeddingProvider(Protocol):
    async def capabilities(self) -> ProviderCapabilities: ...

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse: ...


@runtime_checkable
class GenerationProvider(Protocol):
    async def capabilities(self) -> ProviderCapabilities: ...

    async def generate(self, request: GenerationRequest) -> GenerationResponse: ...
