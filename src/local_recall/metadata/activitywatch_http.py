from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Never
from urllib.parse import parse_qs, unquote, urlsplit

from .activitywatch_types import (
    MAX_BUCKET_BODY_BYTES,
    MAX_HEADER_BYTES,
    ActivityWatchAdapterFailure,
    ActivityWatchMetadataFailureCode,
    contains_control,
    require_aware,
)

_ALLOWED_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_ALLOWED_FIXED_TARGETS = frozenset({"/api/0/info", "/api/0/buckets/"})
_MAX_QUERY_RANGE_SECONDS = 10.0


class LoopbackActivityWatchTransport:
    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:5600",
        *,
        connect_timeout_seconds: float = 0.25,
        request_timeout_seconds: float = 0.75,
        max_header_bytes: int = MAX_HEADER_BYTES,
    ) -> None:
        host, port = parse_loopback_origin(endpoint)
        if connect_timeout_seconds <= 0.0 or request_timeout_seconds <= 0.0:
            raise ValueError("ActivityWatch transport timeouts must be positive")
        if not 1024 <= max_header_bytes <= MAX_HEADER_BYTES:
            raise ValueError("ActivityWatch response-header limit is invalid")
        self._host = host
        self._port = port
        self._connect_timeout_seconds = connect_timeout_seconds
        self._request_timeout_seconds = request_timeout_seconds
        self._max_header_bytes = max_header_bytes

    def __repr__(self) -> str:
        return "LoopbackActivityWatchTransport(endpoint=<loopback>, proxy_support=False)"

    async def get(
        self,
        target: str,
        *,
        max_response_bytes: int,
        timeout_seconds: float | None = None,
    ) -> bytes:
        _validate_target(target)
        if not 1 <= max_response_bytes <= MAX_BUCKET_BODY_BYTES:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.INVALID_REQUEST)

        request_timeout = self._request_timeout_seconds
        if timeout_seconds is not None:
            if timeout_seconds <= 0.0:
                raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.TIMEOUT)
            request_timeout = min(request_timeout, timeout_seconds)
        connect_timeout = min(self._connect_timeout_seconds, request_timeout)

        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(connect_timeout):
                reader, writer = await asyncio.open_connection(
                    self._host,
                    self._port,
                    limit=self._max_header_bytes + 1,
                )
            async with asyncio.timeout(request_timeout):
                writer.write(self._request_bytes(target))
                await writer.drain()
                return await self._read_response(
                    reader,
                    max_response_bytes=max_response_bytes,
                )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.TIMEOUT) from None
        except ActivityWatchAdapterFailure:
            raise
        except OSError, ConnectionError:
            raise ActivityWatchAdapterFailure(
                ActivityWatchMetadataFailureCode.UNAVAILABLE
            ) from None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError, ConnectionError:
                    pass

    def _request_bytes(self, target: str) -> bytes:
        host_header = f"[{self._host}]" if ":" in self._host else self._host
        if self._port != 80:
            host_header = f"{host_header}:{self._port}"
        return (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n"
            "User-Agent: local-recall-activitywatch/1\r\n"
            "\r\n"
        ).encode("ascii")

    async def _read_response(
        self,
        reader: asyncio.StreamReader,
        *,
        max_response_bytes: int,
    ) -> bytes:
        try:
            header_block = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            raise ActivityWatchAdapterFailure(
                ActivityWatchMetadataFailureCode.HEADERS_TOO_LARGE
            ) from None
        except asyncio.IncompleteReadError:
            raise ActivityWatchAdapterFailure(
                ActivityWatchMetadataFailureCode.INCOMPLETE_RESPONSE
            ) from None

        if len(header_block) > self._max_header_bytes:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.HEADERS_TOO_LARGE)

        status, headers = _parse_http_headers(header_block)
        if 300 <= status <= 399:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.REDIRECT)
        if status != 200:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.HTTP_STATUS)
        if "transfer-encoding" in headers:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_HTTP)

        content_lengths = headers.get("content-length", ())
        if len(content_lengths) != 1:
            raise ActivityWatchAdapterFailure(
                ActivityWatchMetadataFailureCode.INVALID_CONTENT_LENGTH
            )
        raw_length = content_lengths[0]
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise ActivityWatchAdapterFailure(
                ActivityWatchMetadataFailureCode.INVALID_CONTENT_LENGTH
            )
        length = int(raw_length)
        if length > max_response_bytes:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.RESPONSE_TOO_LARGE)

        try:
            return await reader.readexactly(length)
        except asyncio.IncompleteReadError:
            raise ActivityWatchAdapterFailure(
                ActivityWatchMetadataFailureCode.INCOMPLETE_RESPONSE
            ) from None


def parse_loopback_origin(endpoint: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("ActivityWatch endpoint must be an HTTP loopback origin") from exc

    hostname = parsed.hostname
    if (
        parsed.scheme != "http"
        or hostname not in _ALLOWED_LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("ActivityWatch endpoint must be an HTTP loopback origin")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("ActivityWatch endpoint must be an HTTP loopback origin")
    return hostname, port or 80


def _validate_target(target: str) -> None:
    if target in _ALLOWED_FIXED_TARGETS:
        return

    parsed = urlsplit(target)
    components = parsed.path.split("/")
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or len(components) != 6
        or components[:4] != ["", "api", "0", "buckets"]
        or components[5] != "events"
    ):
        _invalid_request()

    bucket_id = unquote(components[4])
    if not bucket_id or len(bucket_id) > 256 or "/" in bucket_id or contains_control(bucket_id):
        _invalid_request()

    try:
        query = parse_qs(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=3,
        )
        if set(query) != {"start", "end", "limit"}:
            _invalid_request()
        if any(len(values) != 1 for values in query.values()):
            _invalid_request()
        limit = int(query["limit"][0])
        start = datetime.fromisoformat(query["start"][0])
        end = datetime.fromisoformat(query["end"][0])
        require_aware(start)
        require_aware(end)
    except KeyError, TypeError, ValueError:
        _invalid_request()

    if (
        not 1 <= limit <= 16
        or end <= start
        or (end - start).total_seconds() > _MAX_QUERY_RANGE_SECONDS
    ):
        _invalid_request()


def _invalid_request() -> Never:
    raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.INVALID_REQUEST)


def _parse_http_headers(
    payload: bytes,
) -> tuple[int, dict[str, tuple[str, ...]]]:
    text = payload.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or lines[-2:] != ["", ""]:
        raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_HTTP)

    parts = lines[0].split(" ")
    if (
        len(parts) < 2
        or parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(parts[1]) != 3
        or not parts[1].isdigit()
    ):
        raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_HTTP)

    headers: dict[str, list[str]] = {}
    for line in lines[1:-2]:
        if not line or line[0] in " \t" or ":" not in line:
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_HTTP)
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or contains_control(name) or contains_control(value):
            raise ActivityWatchAdapterFailure(ActivityWatchMetadataFailureCode.MALFORMED_HTTP)
        headers.setdefault(name, []).append(value)

    return int(parts[1]), {name: tuple(values) for name, values in headers.items()}
