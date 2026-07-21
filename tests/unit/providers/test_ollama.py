from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any

import pytest

from local_recall.domain import (
    GenerationRequest,
    GenerationRole,
    ModelCapability,
    PrivacyClass,
)
from local_recall.providers.ollama import (
    OllamaGenerationProvider,
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


def settings(
    *, timeout_seconds: float = 0.05, max_input_bytes: int = 1024 * 1024
) -> OllamaSettings:
    return OllamaSettings(
        extraction_model="qwen2.5:7b",
        summarization_model="gemma3:9b",
        answering_model="llama3.1:8b",
        timeout_seconds=timeout_seconds,
        max_input_bytes=max_input_bytes,
    )


def request(role: GenerationRole = GenerationRole.ANSWERING) -> GenerationRequest:
    return GenerationRequest(
        prompt="What was completed?",
        context=("09:00 wrote tests", "09:15 implemented provider"),
        privacy_class=PrivacyClass.REDACTED_CONTENT,
        max_output_tokens=64,
        role=role,
    )


def test_capabilities_discover_context_vision_structured_output_and_availability() -> None:
    transport = FakeTransport(
        [
            {
                "details": {"families": ["gemma3", "clip"]},
                "model_info": {"gemma3.context_length": 8192},
                "capabilities": ["completion", "vision"],
            }
        ]
    )
    provider = OllamaGenerationProvider(settings(), transport=transport)

    capabilities = asyncio.run(provider.capabilities())

    assert capabilities.available
    assert capabilities.max_context_tokens == 8192
    assert capabilities.supports_structured_output
    assert capabilities.supports_vision
    assert ModelCapability.VISION in capabilities.capabilities
    assert transport.requests[0][0] == "/api/show"
    assert transport.requests[0][1] == {"model": "llama3.1:8b", "verbose": False}


@pytest.mark.parametrize(
    ("role", "model"),
    [
        (GenerationRole.EXTRACTION, "qwen2.5:7b"),
        (GenerationRole.SUMMARIZATION, "gemma3:9b"),
        (GenerationRole.ANSWERING, "llama3.1:8b"),
    ],
)
def test_generate_selects_configured_role_model_and_validates_schema(
    role: GenerationRole, model: str
) -> None:
    transport = FakeTransport(
        [
            {
                "model": model,
                "response": json.dumps({"text": "Implemented the local provider."}),
                "prompt_eval_count": 24,
                "eval_count": 7,
            }
        ]
    )
    provider = OllamaGenerationProvider(settings(), transport=transport)

    response = asyncio.run(provider.generate(request(role)))

    assert response.text == "Implemented the local provider."
    assert response.input_tokens == 24
    assert response.output_tokens == 7
    payload = transport.requests[0][1]
    assert payload["model"] == model
    assert payload["stream"] is False
    assert payload["format"]["required"] == ["text"]
    assert "Never reproduce, reconstruct, or retain secrets" in payload["prompt"]


def test_generate_rejects_unredacted_content_before_transport() -> None:
    transport = FakeTransport([])
    provider = OllamaGenerationProvider(settings(), transport=transport)
    unsafe = GenerationRequest(
        prompt="summarize",
        context=("raw",),
        privacy_class=PrivacyClass.RAW_CAPTURE,
        max_output_tokens=16,
    )

    with pytest.raises(OllamaProviderError, match="privacy class"):
        asyncio.run(provider.generate(unsafe))

    assert transport.requests == []


def test_generate_makes_no_request_while_capture_is_active() -> None:
    transport = FakeTransport([])
    provider = OllamaGenerationProvider(
        settings(), transport=transport, capture_active=lambda: True
    )

    with pytest.raises(OllamaProviderError, match="capture is active"):
        asyncio.run(provider.generate(request()))

    assert transport.requests == []


def test_generate_rejects_oversized_prompt_before_transport() -> None:
    transport = FakeTransport([])
    provider = OllamaGenerationProvider(settings(max_input_bytes=64), transport=transport)

    with pytest.raises(OllamaProviderError, match="input exceeds"):
        asyncio.run(provider.generate(request()))

    assert transport.requests == []


def test_generate_times_out_and_releases_concurrency_slot() -> None:
    transport = FakeTransport([])
    provider = OllamaGenerationProvider(settings(), transport=transport)

    with pytest.raises(OllamaProviderError, match="timed out"):
        asyncio.run(provider.generate(request()))

    transport.responses.append({"model": "llama3.1:8b", "response": '{"text":"ok"}'})
    assert asyncio.run(provider.generate(request())).text == "ok"


def test_generate_propagates_task_cancellation() -> None:
    async def exercise() -> None:
        transport = FakeTransport([])
        provider = OllamaGenerationProvider(settings(timeout_seconds=5), transport=transport)
        task = asyncio.create_task(provider.generate(request()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "response",
    [
        {"model": "llama3.1:8b", "response": "not-json"},
        {"model": "llama3.1:8b", "response": "{}"},
        {"model": "llama3.1:8b", "response": '{"text":"", "extra":true}'},
    ],
)
def test_generate_rejects_malformed_model_output(response: Mapping[str, Any]) -> None:
    provider = OllamaGenerationProvider(settings(), transport=FakeTransport([response]))

    with pytest.raises(OllamaProviderError, match="invalid structured output"):
        asyncio.run(provider.generate(request()))
