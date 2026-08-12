from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import pytest

from local_recall.domain import EmbeddingRequest, ModelCapability, PrivacyClass
from local_recall.providers.ollama import (
    OllamaEmbeddingProvider,
    OllamaProviderError,
    OllamaSettings,
)


class FakeTransport:
    def __init__(self, responses: list[Mapping[str, Any]]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, Mapping[str, Any], int]] = []
        self.block = asyncio.Event()

    async def request_json(
        self, path: str, payload: Mapping[str, Any], max_response_bytes: int
    ) -> Mapping[str, Any]:
        self.requests.append((path, payload, max_response_bytes))
        if not self.responses:
            await self.block.wait()
            raise AssertionError("unreachable")
        return self.responses.pop(0)


def settings(*, batch_size: int = 2, timeout_seconds: float = 0.05) -> OllamaSettings:
    return OllamaSettings(
        extraction_model="extract-model",
        summarization_model="summary-model",
        answering_model="answer-model",
        embedding_model="embed-model",
        embedding_batch_size=batch_size,
        timeout_seconds=timeout_seconds,
    )


def request(*values: str) -> EmbeddingRequest:
    return EmbeddingRequest(inputs=values, privacy_class=PrivacyClass.REDACTED_CONTENT)


def test_embedding_provider_batches_locally_and_returns_typed_vectors() -> None:
    transport = FakeTransport(
        [
            {"model": "embed-model", "embeddings": [[1.0, 0.0], [0.0, 1.0]]},
            {"model": "embed-model", "embeddings": [[0.5, 0.5]]},
        ]
    )
    provider = OllamaEmbeddingProvider(settings(), transport=transport)

    response = asyncio.run(provider.embed(request("one", "two", "three")))

    assert response.model_id == "embed-model"
    assert response.vectors == ((1.0, 0.0), (0.0, 1.0), (0.5, 0.5))
    assert [call[1]["input"] for call in transport.requests] == [
        ["one", "two"],
        ["three"],
    ]


def test_embedding_provider_capabilities_are_local_and_embedding_only() -> None:
    transport = FakeTransport([{"model_info": {"embed.context_length": 4096}}])
    provider = OllamaEmbeddingProvider(settings(), transport=transport)

    capabilities = asyncio.run(provider.capabilities())

    assert capabilities.capabilities == frozenset({ModelCapability.EMBEDDING})
    assert capabilities.max_context_tokens == 4096
    assert capabilities.accepts(PrivacyClass.REDACTED_CONTENT)
    assert transport.requests[0][1] == {"model": "embed-model", "verbose": False}


def test_embedding_provider_rejects_unredacted_input_before_transport() -> None:
    transport = FakeTransport([])
    provider = OllamaEmbeddingProvider(settings(), transport=transport)
    unsafe = EmbeddingRequest(inputs=("raw",), privacy_class=PrivacyClass.RAW_CAPTURE)

    with pytest.raises(OllamaProviderError, match="privacy class"):
        asyncio.run(provider.embed(unsafe))

    assert transport.requests == []


def test_embedding_provider_rejects_dimension_or_count_drift() -> None:
    provider = OllamaEmbeddingProvider(
        settings(),
        transport=FakeTransport([{"model": "embed-model", "embeddings": [[1.0, 0.0], [1.0]]}]),
    )

    with pytest.raises(OllamaProviderError, match="invalid embedding response"):
        asyncio.run(provider.embed(request("one", "two")))


def test_embedding_provider_propagates_cancellation() -> None:
    async def exercise() -> None:
        provider = OllamaEmbeddingProvider(settings(timeout_seconds=5), transport=FakeTransport([]))
        task = asyncio.create_task(provider.embed(request("one")))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())
