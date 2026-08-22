from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, cast
from urllib.parse import urlsplit

from local_recall.routing import ApprovedEgressPayload, EgressDataClass


class RemoteProviderKind(StrEnum):
    OPENAI_COMPATIBLE = "openai-compatible"
    OPENROUTER = "openrouter"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"


class RemoteRequestError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if not reason_code:
            raise ValueError("remote request reason code must not be empty")
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:
        return f"RemoteRequestError(reason_code={self.reason_code!r})"


class RemoteTransportError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if not reason_code:
            raise ValueError("remote transport reason code must not be empty")
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:
        return f"RemoteTransportError(reason_code={self.reason_code!r})"


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedCredential:
    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("resolved credential must not be empty")
        if any(character in self.value for character in ("\x00", "\r", "\n")):
            raise ValueError("resolved credential contains invalid characters")


@dataclass(frozen=True, slots=True)
class RemoteProviderSpec:
    provider_id: str
    kind: RemoteProviderKind
    endpoint: str = field(repr=False)
    model_id: str

    def __post_init__(self) -> None:
        if not self.provider_id:
            raise ValueError("remote provider id must not be empty")
        if not self.model_id:
            raise ValueError("remote model id must not be empty")
        if any(character in self.model_id for character in ("\x00", "\r", "\n")):
            raise ValueError("remote model id contains invalid characters")
        try:
            parsed = urlsplit(self.endpoint)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("remote endpoint must be a valid HTTPS URL") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith("/")
            or parsed.path == "/"
            or parsed.query
            or parsed.fragment
            or any(character in parsed.path for character in ("\x00", "\r", "\n"))
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("remote endpoint must be a valid HTTPS URL")


@dataclass(frozen=True, slots=True)
class RemoteHttpRequest:
    method: str
    origin: str
    path: str
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class RemoteTransportSettings:
    timeout_seconds: float = 30.0
    max_request_bytes: int = 1024 * 1024
    max_response_bytes: int = 1024 * 1024
    max_header_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("remote timeout must be positive")
        if self.max_request_bytes <= 0:
            raise ValueError("remote request limit must be positive")
        if self.max_response_bytes <= 0:
            raise ValueError("remote response limit must be positive")
        if self.max_header_bytes <= 0:
            raise ValueError("remote header limit must be positive")


class _RemoteReader(Protocol):
    async def readuntil(self, separator: bytes = b"\n") -> bytes: ...

    async def readexactly(self, count: int) -> bytes: ...


class _RemoteWriter(Protocol):
    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


_RemoteConnector = Callable[
    [str, int, object, str], Awaitable[tuple[_RemoteReader, _RemoteWriter]]
]


async def _open_tls_connection(
    host: str, port: int, ssl_context: object, server_hostname: str
) -> tuple[_RemoteReader, _RemoteWriter]:
    if not isinstance(ssl_context, ssl.SSLContext):
        raise RemoteTransportError("remote-tls-context-invalid")
    reader, writer = await asyncio.open_connection(
        host,
        port,
        ssl=ssl_context,
        server_hostname=server_hostname,
    )
    return reader, writer


class RemoteHttpsTransport:
    def __init__(
        self,
        settings: RemoteTransportSettings,
        *,
        connector: _RemoteConnector | None = None,
    ) -> None:
        self._settings = settings
        self._connector = connector or _open_tls_connection
        self._ssl_context = ssl.create_default_context()

    async def request_json(self, request: RemoteHttpRequest) -> Mapping[str, object]:
        host, port = self._target(request)
        wire_request = self._serialize(request, host, port)
        if len(wire_request) > self._settings.max_request_bytes:
            raise RemoteTransportError("remote-request-too-large")

        writer: _RemoteWriter | None = None
        try:
            async with asyncio.timeout(self._settings.timeout_seconds):
                reader, writer = await self._connector(
                    host,
                    port,
                    self._ssl_context,
                    host,
                )
                writer.write(wire_request)
                await writer.drain()
                header_block = await reader.readuntil(b"\r\n\r\n")
                if len(header_block) > self._settings.max_header_bytes:
                    raise RemoteTransportError("remote-response-headers-too-large")
                status, headers = self._parse_headers(header_block)
                if 300 <= status <= 399:
                    raise RemoteTransportError("remote-redirect-denied")
                if status != 200:
                    raise RemoteTransportError("remote-http-error")
                if "transfer-encoding" in headers:
                    raise RemoteTransportError("remote-transfer-encoding-denied")
                content_length = headers.get("content-length")
                if content_length is None or not content_length.isdecimal():
                    raise RemoteTransportError("remote-content-length-invalid")
                size = int(content_length)
                if size > self._settings.max_response_bytes:
                    raise RemoteTransportError("remote-response-too-large")
                body = await reader.readexactly(size)
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            raise RemoteTransportError("remote-timeout") from exc
        except RemoteTransportError:
            raise
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise RemoteTransportError("remote-response-incomplete") from exc
        except (OSError, ssl.SSLError) as exc:
            raise RemoteTransportError("remote-connection-failed") from exc
        except Exception as exc:
            raise RemoteTransportError("remote-transport-failed") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    pass

        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemoteTransportError("remote-json-invalid") from exc
        if not isinstance(decoded, dict):
            raise RemoteTransportError("remote-json-envelope-invalid")
        return cast(Mapping[str, object], decoded)

    @staticmethod
    def _target(request: RemoteHttpRequest) -> tuple[str, int]:
        parsed = urlsplit(request.origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise RemoteTransportError("remote-origin-invalid")
        try:
            port = parsed.port or 443
        except ValueError as exc:
            raise RemoteTransportError("remote-origin-invalid") from exc
        return parsed.hostname, port

    @staticmethod
    def _serialize(request: RemoteHttpRequest, host: str, port: int) -> bytes:
        if request.method != "POST":
            raise RemoteTransportError("remote-method-denied")
        if (
            not request.path.startswith("/")
            or any(character in request.path for character in ("\x00", "\r", "\n"))
        ):
            raise RemoteTransportError("remote-path-invalid")
        header_lines: list[str] = []
        for name, value in request.headers.items():
            normalized = name.lower()
            if (
                not normalized
                or not all(character.isalnum() or character == "-" for character in normalized)
                or any(character in value for character in ("\x00", "\r", "\n"))
                or normalized in {"host", "content-length", "connection"}
            ):
                raise RemoteTransportError("remote-header-invalid")
            header_lines.append(f"{normalized}: {value}")
        host_header = host if port == 443 else f"{host}:{port}"
        prefix = (
            f"POST {request.path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: {len(request.body)}\r\n"
            "Connection: close\r\n"
            + "\r\n".join(header_lines)
            + "\r\n\r\n"
        ).encode("ascii")
        return prefix + request.body

    @staticmethod
    def _parse_headers(block: bytes) -> tuple[int, Mapping[str, str]]:
        try:
            text = block.decode("iso-8859-1")
            lines = text.split("\r\n")
            status_parts = lines[0].split(" ", 2)
            if len(status_parts) < 2 or status_parts[0] != "HTTP/1.1":
                raise ValueError
            status = int(status_parts[1])
        except (UnicodeDecodeError, ValueError, IndexError) as exc:
            raise RemoteTransportError("remote-response-headers-invalid") from exc
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise RemoteTransportError("remote-response-headers-invalid")
            name, value = line.split(":", 1)
            normalized = name.strip().lower()
            if not normalized or normalized in headers:
                raise RemoteTransportError("remote-response-headers-invalid")
            headers[normalized] = value.strip()
        return status, MappingProxyType(headers)


class RemoteRequestBuilder:
    def build(
        self,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        if approved.provider_id != spec.provider_id:
            raise RemoteRequestError("provider-authorization-mismatch")
        if self._present_data_classes(approved) != approved.data_classes:
            raise RemoteRequestError("approved-payload-class-mismatch")
        self._require_text_only(approved)

        if spec.kind is RemoteProviderKind.OPENROUTER:
            return self._build_openrouter(spec, approved, credential)
        if spec.kind is RemoteProviderKind.OPENAI_COMPATIBLE:
            return self._build_openai_compatible(spec, approved, credential)
        if spec.kind is RemoteProviderKind.ANTHROPIC:
            return self._build_anthropic(spec, approved, credential)
        if spec.kind is RemoteProviderKind.GOOGLE:
            return self._build_google(spec, approved, credential)
        raise RemoteRequestError("unsupported-remote-provider")

    @staticmethod
    def _present_data_classes(
        approved: ApprovedEgressPayload,
    ) -> frozenset[EgressDataClass]:
        classes: set[EgressDataClass] = set()
        if approved.text:
            classes.add(EgressDataClass.REDACTED_TEXT)
        if approved.metadata:
            classes.add(EgressDataClass.APPROVED_METADATA)
        if approved.image:
            classes.add(EgressDataClass.REDACTED_IMAGE)
        return frozenset(classes)

    @staticmethod
    def _require_text_only(approved: ApprovedEgressPayload) -> None:
        if approved.metadata or approved.image:
            raise RemoteRequestError("unsupported-egress-modality")
        if not approved.text:
            raise RemoteRequestError("remote-text-required")

    @staticmethod
    def _endpoint_parts(spec: RemoteProviderSpec) -> tuple[str, str]:
        parsed = urlsplit(spec.endpoint)
        if not parsed.hostname:
            raise RemoteRequestError("invalid-remote-endpoint")
        origin = f"https://{parsed.hostname}"
        if parsed.port is not None:
            origin = f"{origin}:{parsed.port}"
        return origin, parsed.path

    @staticmethod
    def _json_body(payload: object) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def _build_openrouter(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "authorization": f"Bearer {credential.value}",
                    "content-type": "application/json",
                }
            ),
            body=cls._json_body(
                {
                    "messages": [{"role": "user", "content": approved.text}],
                    "model": spec.model_id,
                    "provider": {"allow_fallbacks": False},
                }
            ),
        )

    @classmethod
    def _build_openai_compatible(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "authorization": f"Bearer {credential.value}",
                    "content-type": "application/json",
                }
            ),
            body=cls._json_body(
                {
                    "messages": [{"role": "user", "content": approved.text}],
                    "model": spec.model_id,
                }
            ),
        )

    @classmethod
    def _build_anthropic(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                    "x-api-key": credential.value,
                }
            ),
            body=cls._json_body(
                {
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": approved.text}],
                    "model": spec.model_id,
                }
            ),
        )

    @classmethod
    def _build_google(
        cls,
        spec: RemoteProviderSpec,
        approved: ApprovedEgressPayload,
        credential: ResolvedCredential,
    ) -> RemoteHttpRequest:
        origin, path = cls._endpoint_parts(spec)
        expected_suffix = f"/models/{spec.model_id}:generateContent"
        if not path.endswith(expected_suffix):
            raise RemoteRequestError("provider-endpoint-model-mismatch")
        return RemoteHttpRequest(
            method="POST",
            origin=origin,
            path=path,
            headers=MappingProxyType(
                {
                    "content-type": "application/json",
                    "x-goog-api-key": credential.value,
                }
            ),
            body=cls._json_body({"contents": [{"parts": [{"text": approved.text}]}]}),
        )
