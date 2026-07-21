from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from local_recall.domain import (
    GenerationRequest,
    GenerationResponse,
    GenerationRole,
    ModelCapability,
    PrivacyClass,
    ProviderCapabilities,
    ProviderLocation,
)

_OUTPUT_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
    "additionalProperties": False,
}
_SYSTEM_INSTRUCTION = (
    "Use only the supplied, deterministically redacted context. "
    "Never reproduce, reconstruct, or retain secrets. "
    "Return exactly one JSON object matching the supplied schema."
)


class OllamaProviderError(RuntimeError):
    """A sanitized Ollama provider failure."""


class OllamaTransport(Protocol):
    async def request_json(
        self, path: str, payload: Mapping[str, Any], max_response_bytes: int
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class OllamaSettings:
    extraction_model: str
    summarization_model: str
    answering_model: str
    base_url: str = "http://127.0.0.1:11434"
    timeout_seconds: float = 30.0
    max_concurrency: int = 1
    max_input_bytes: int = 1024 * 1024
    max_response_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        models = (self.extraction_model, self.summarization_model, self.answering_model)
        if any(not model.strip() for model in models):
            raise ValueError("Ollama model identifiers must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        if self.max_input_bytes <= 0 or self.max_response_bytes <= 0:
            raise ValueError("Ollama byte limits must be positive")
        _parse_local_endpoint(self.base_url)

    def model_for(self, request: GenerationRequest) -> str:
        if request.model_hint is not None:
            if not request.model_hint.strip():
                raise OllamaProviderError("model hint must not be empty")
            return request.model_hint
        return {
            GenerationRole.EXTRACTION: self.extraction_model,
            GenerationRole.SUMMARIZATION: self.summarization_model,
            GenerationRole.ANSWERING: self.answering_model,
        }[request.role]


class OllamaGenerationProvider:
    def __init__(
        self,
        settings: OllamaSettings,
        *,
        transport: OllamaTransport | None = None,
        capture_active: Callable[[], bool] = lambda: False,
    ) -> None:
        self._settings = settings
        self._transport = transport or LocalOllamaTransport(settings.base_url)
        self._capture_active = capture_active
        self._capacity = asyncio.Semaphore(settings.max_concurrency)

    async def capabilities(self) -> ProviderCapabilities:
        response = await self._request(
            "/api/show",
            {"model": self._settings.answering_model, "verbose": False},
        )
        advertised = _string_set(response.get("capabilities"))
        details = _mapping(response.get("details"))
        families = _string_set(details.get("families"))
        vision = "vision" in advertised or "clip" in families
        capabilities = {ModelCapability.GENERATION}
        if vision:
            capabilities.add(ModelCapability.VISION)
        return ProviderCapabilities(
            provider_id="ollama",
            location=ProviderLocation.LOCAL,
            capabilities=frozenset(capabilities),
            accepted_privacy_classes=frozenset({PrivacyClass.REDACTED_CONTENT}),
            max_input_bytes=self._settings.max_input_bytes,
            supports_vision=vision,
            max_context_tokens=_context_length(response.get("model_info")),
            supports_structured_output=True,
            available=True,
        )

    async def generate(self, request: GenerationRequest) -> GenerationResponse:
        if request.privacy_class is not PrivacyClass.REDACTED_CONTENT:
            raise OllamaProviderError("Ollama rejects this privacy class")
        prompt = _build_prompt(request)
        if len(prompt.encode()) > self._settings.max_input_bytes:
            raise OllamaProviderError("Ollama input exceeds configured byte limit")
        model = self._settings.model_for(request)
        response = await self._request(
            "/api/generate",
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": _OUTPUT_SCHEMA,
                "options": {"num_predict": request.max_output_tokens},
            },
        )
        text = _structured_text(response.get("response"))
        response_model = response.get("model")
        if not isinstance(response_model, str) or not response_model.strip():
            raise OllamaProviderError("Ollama returned an invalid response envelope")
        return GenerationResponse(
            text=text,
            provider_id="ollama",
            model_id=response_model,
            input_tokens=_optional_count(response.get("prompt_eval_count")),
            output_tokens=_optional_count(response.get("eval_count")),
        )

    async def _request(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._capture_active():
            raise OllamaProviderError("Ollama requests are disabled while capture is active")
        try:
            async with self._capacity:
                async with asyncio.timeout(self._settings.timeout_seconds):
                    return await self._transport.request_json(
                        path, payload, self._settings.max_response_bytes
                    )
        except TimeoutError as exc:
            raise OllamaProviderError("Ollama request timed out") from exc
        except asyncio.CancelledError:
            raise
        except OllamaProviderError:
            raise
        except Exception as exc:
            raise OllamaProviderError("Ollama request failed") from exc


class LocalOllamaTransport:
    """Small cancellation-safe HTTP client restricted to a loopback Ollama endpoint."""

    def __init__(self, base_url: str) -> None:
        self._host, self._port = _parse_local_endpoint(base_url)

    async def request_json(
        self, path: str, payload: Mapping[str, Any], max_response_bytes: int
    ) -> Mapping[str, Any]:
        if not path.startswith("/api/") or "\r" in path or "\n" in path:
            raise OllamaProviderError("invalid Ollama API path")
        body = json.dumps(payload, separators=(",", ":")).encode()
        reader, writer = await asyncio.open_connection(self._host, self._port)
        try:
            writer.write(
                (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {self._host}:{self._port}\r\n"
                    "Content-Type: application/json\r\n"
                    "Connection: close\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode("ascii")
                + body
            )
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
            if len(header) > 16 * 1024:
                raise OllamaProviderError("Ollama response headers exceed limit")
            status, headers = _parse_headers(header)
            if status != 200:
                raise OllamaProviderError(f"Ollama returned HTTP status {status}")
            length = headers.get("content-length")
            if length is None or not length.isdecimal():
                raise OllamaProviderError("Ollama response has no valid content length")
            size = int(length)
            if size > max_response_bytes:
                raise OllamaProviderError("Ollama response exceeds configured byte limit")
            response_body = await reader.readexactly(size)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise OllamaProviderError("Ollama returned an incomplete response") from exc
        finally:
            writer.close()
            await writer.wait_closed()
        try:
            value = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OllamaProviderError("Ollama returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise OllamaProviderError("Ollama returned an invalid response envelope")
        return cast(Mapping[str, Any], value)


def _parse_local_endpoint(base_url: str) -> tuple[str, int]:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Ollama base URL must be an HTTP loopback origin")
    return parsed.hostname, parsed.port or 11434


def _build_prompt(request: GenerationRequest) -> str:
    context = "\n".join(f"- {item}" for item in request.context)
    return f"{_SYSTEM_INSTRUCTION}\n\nContext:\n{context}\n\nTask:\n{request.prompt}"


def _mapping(value: object) -> Mapping[str, object]:
    return cast(Mapping[str, object], value) if isinstance(value, dict) else {}


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    items = cast(list[object], value)
    return {item for item in items if isinstance(item, str)}


def _context_length(value: object) -> int | None:
    candidates = [item for key, item in _mapping(value).items() if key.endswith(".context_length")]
    valid = [item for item in candidates if isinstance(item, int) and item > 0]
    return max(valid, default=None)


def _structured_text(value: object) -> str:
    try:
        decoded = json.loads(value) if isinstance(value, str) else None
    except json.JSONDecodeError as exc:
        raise OllamaProviderError("Ollama returned invalid structured output") from exc
    if not isinstance(decoded, dict):
        raise OllamaProviderError("Ollama returned invalid structured output")
    output = cast(dict[str, object], decoded)
    if set(output) != {"text"}:
        raise OllamaProviderError("Ollama returned invalid structured output")
    text = output.get("text")
    if not isinstance(text, str) or not text.strip():
        raise OllamaProviderError("Ollama returned invalid structured output")
    return text


def _optional_count(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 0:
        raise OllamaProviderError("Ollama returned an invalid token count")
    return value


def _parse_headers(value: bytes) -> tuple[int, dict[str, str]]:
    try:
        lines = value.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers = {
            name.strip().lower(): item.strip()
            for line in lines[1:]
            if ":" in line
            for name, item in [line.split(":", 1)]
        }
    except (IndexError, ValueError) as exc:
        raise OllamaProviderError("Ollama returned invalid HTTP headers") from exc
    return status, headers
