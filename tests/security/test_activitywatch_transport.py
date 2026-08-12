from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable

import pytest

from local_recall.metadata import (
    ActivityWatchAdapterFailure,
    ActivityWatchMetadataFailureCode,
    LoopbackActivityWatchTransport,
)

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def with_server(handler: Handler, operation: Callable[[str], Awaitable[bytes]]) -> bytes:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    sockets = server.sockets
    assert sockets
    port = int(sockets[0].getsockname()[1])
    try:
        return await operation(f"http://127.0.0.1:{port}")
    finally:
        server.close()
        await server.wait_closed()


async def fixed_response(response: bytes, endpoint: str, *, max_body: int = 4096) -> bytes:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def operation(origin: str) -> bytes:
        assert endpoint == "unused"
        transport = LoopbackActivityWatchTransport(origin)
        return await transport.get("/api/0/info", max_response_bytes=max_body)

    return await with_server(handler, operation)


def test_successful_response_is_bounded_and_direct() -> None:
    payload = b'{"hostname":"synthetic-host"}'
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(payload)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + payload
    )

    assert asyncio.run(fixed_response(response, "unused")) == payload


def test_proxy_environment_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.9:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://192.0.2.9:8080")
    monkeypatch.setenv("ALL_PROXY", "http://192.0.2.9:8080")
    payload = b"{}"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"

    assert asyncio.run(fixed_response(response, "unused")) == payload


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (
            b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/escape\r\nContent-Length: 0\r\n\r\n",
            ActivityWatchMetadataFailureCode.REDIRECT,
        ),
        (
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            ActivityWatchMetadataFailureCode.HTTP_STATUS,
        ),
        (
            b"not-http\r\nContent-Length: 0\r\n\r\n",
            ActivityWatchMetadataFailureCode.MALFORMED_HTTP,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
            ActivityWatchMetadataFailureCode.INVALID_CONTENT_LENGTH,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            ActivityWatchMetadataFailureCode.INVALID_CONTENT_LENGTH,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            ActivityWatchMetadataFailureCode.MALFORMED_HTTP,
        ),
    ],
)
def test_malformed_or_redirecting_http_fails_with_fixed_code(
    response: bytes,
    code: ActivityWatchMetadataFailureCode,
) -> None:
    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(fixed_response(response, "unused"))

    assert captured.value.code is code
    assert "192.0.2.1" not in str(captured.value)
    assert "Location" not in str(captured.value)


def test_oversized_headers_fail_before_body_processing() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nX-Fill: "
        + b"a" * (17 * 1024)
        + b"\r\nContent-Length: 0\r\n\r\n"
    )

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(fixed_response(response, "unused"))

    assert captured.value.code is ActivityWatchMetadataFailureCode.HEADERS_TOO_LARGE


def test_oversized_body_is_rejected_from_content_length() -> None:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n"

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(fixed_response(response, "unused", max_body=4096))

    assert captured.value.code is ActivityWatchMetadataFailureCode.RESPONSE_TOO_LARGE


def test_truncated_body_fails_safely() -> None:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(fixed_response(response, "unused"))

    assert captured.value.code is ActivityWatchMetadataFailureCode.INCOMPLETE_RESPONSE


def test_unapproved_api_target_is_rejected_before_connect() -> None:
    transport = LoopbackActivityWatchTransport("http://127.0.0.1:5600")

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(transport.get("/api/0/export", max_response_bytes=1024))

    assert captured.value.code is ActivityWatchMetadataFailureCode.INVALID_REQUEST


def test_request_timeout_is_bounded_and_sanitized() -> None:
    marker = "synthetic-sensitive-server-value"

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        await asyncio.sleep(1)
        writer.write(marker.encode())
        writer.close()
        await writer.wait_closed()

    async def operation(origin: str) -> bytes:
        transport = LoopbackActivityWatchTransport(
            origin,
            connect_timeout_seconds=0.2,
            request_timeout_seconds=0.01,
        )
        return await transport.get("/api/0/info", max_response_bytes=4096)

    with pytest.raises(ActivityWatchAdapterFailure) as captured:
        asyncio.run(with_server(handler, operation))

    assert captured.value.code is ActivityWatchMetadataFailureCode.TIMEOUT
    assert marker not in str(captured.value)


def test_cancellation_propagates_instead_of_becoming_success() -> None:
    async def scenario() -> None:
        started = asyncio.Event()

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            started.set()
            try:
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        sockets = server.sockets
        assert sockets
        port = int(sockets[0].getsockname()[1])
        transport = LoopbackActivityWatchTransport(
            f"http://127.0.0.1:{port}",
            request_timeout_seconds=2.0,
        )
        task = asyncio.create_task(transport.get("/api/0/info", max_response_bytes=4096))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_transport_does_not_consume_proxy_configuration() -> None:
    transport = LoopbackActivityWatchTransport("http://127.0.0.1:5600")

    representation = repr(transport)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        assert os.environ.get(name, "") not in representation
