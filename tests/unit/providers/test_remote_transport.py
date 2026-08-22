from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from importlib import import_module
from typing import cast

import pytest

remote = import_module("local_recall.providers.remote")
RemoteHttpRequest = remote.RemoteHttpRequest
RemoteHttpsTransport = remote.RemoteHttpsTransport
RemoteTransportError = remote.RemoteTransportError
RemoteTransportSettings = remote.RemoteTransportSettings


class FakeWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class FakeReader:
    def __init__(self, response: bytes) -> None:
        self._buffer = bytearray(response)

    async def readuntil(self, separator: bytes = b"\n") -> bytes:
        index = self._buffer.find(separator)
        if index < 0:
            raise asyncio.IncompleteReadError(bytes(self._buffer), None)
        end = index + len(separator)
        value = bytes(self._buffer[:end])
        del self._buffer[:end]
        return value

    async def readexactly(self, count: int) -> bytes:
        if len(self._buffer) < count:
            partial = bytes(self._buffer)
            self._buffer.clear()
            raise asyncio.IncompleteReadError(partial, count)
        value = bytes(self._buffer[:count])
        del self._buffer[:count]
        return value


Connector = Callable[[str, int, object, str], Awaitable[tuple[FakeReader, FakeWriter]]]


def _request() -> object:
    return RemoteHttpRequest(
        method="POST",
        origin="https://api.example.test",
        path="/v1/messages",
        headers={"authorization": "Bearer synthetic-secret"},
        body=b'{"safe":"payload"}',
    )


def _response(status: int, body: bytes, *, extra_headers: bytes = b"") -> bytes:
    return (
        f"HTTP/1.1 {status} Test\r\n".encode()
        + f"Content-Length: {len(body)}\r\n".encode()
        + extra_headers
        + b"Content-Type: application/json\r\nConnection: close\r\n\r\n"
        + body
    )


def test_transport_uses_direct_tls_origin_and_returns_bounded_json() -> None:
    writer = FakeWriter()
    seen: list[tuple[str, int, object, str]] = []

    async def connect(host: str, port: int, ssl_context: object, server_hostname: str):
        seen.append((host, port, ssl_context, server_hostname))
        return FakeReader(_response(200, b'{"ok":true}')), writer

    async def scenario() -> None:
        transport = RemoteHttpsTransport(
            RemoteTransportSettings(timeout_seconds=1.0),
            connector=cast(Connector, connect),
        )
        response = await transport.request_json(_request())
        assert response == {"ok": True}

    asyncio.run(scenario())

    assert seen[0][0] == "api.example.test"
    assert seen[0][1] == 443
    assert seen[0][3] == "api.example.test"
    assert seen[0][2] is not None
    assert b"POST /v1/messages HTTP/1.1\r\n" in writer.data
    assert b"Host: api.example.test\r\n" in writer.data
    assert b"Connection: close\r\n" in writer.data
    assert writer.closed


def test_redirect_is_denied_and_location_is_not_followed() -> None:
    writer = FakeWriter()

    async def connect(host: str, port: int, ssl_context: object, server_hostname: str):
        return (
            FakeReader(
                _response(
                    302,
                    b"{}",
                    extra_headers=b"Location: https://other.example/steal\r\n",
                )
            ),
            writer,
        )

    async def scenario() -> None:
        transport = RemoteHttpsTransport(
            RemoteTransportSettings(timeout_seconds=1.0),
            connector=cast(Connector, connect),
        )
        with pytest.raises(RemoteTransportError, match="remote-redirect-denied"):
            await transport.request_json(_request())

    asyncio.run(scenario())
    assert writer.closed


def test_response_body_limit_fails_before_reading_payload() -> None:
    writer = FakeWriter()
    body = json.dumps({"value": "x" * 100}).encode()

    async def connect(host: str, port: int, ssl_context: object, server_hostname: str):
        return FakeReader(_response(200, body)), writer

    async def scenario() -> None:
        transport = RemoteHttpsTransport(
            RemoteTransportSettings(timeout_seconds=1.0, max_response_bytes=32),
            connector=cast(Connector, connect),
        )
        with pytest.raises(RemoteTransportError, match="remote-response-too-large"):
            await transport.request_json(_request())

    asyncio.run(scenario())
    assert writer.closed


def test_redirect_and_transport_errors_do_not_render_secret_headers_or_body() -> None:
    writer = FakeWriter()

    async def connect(host: str, port: int, ssl_context: object, server_hostname: str):
        return FakeReader(_response(500, b'{"error":"private body"}')), writer

    async def scenario() -> None:
        transport = RemoteHttpsTransport(
            RemoteTransportSettings(timeout_seconds=1.0),
            connector=cast(Connector, connect),
        )
        with pytest.raises(RemoteTransportError, match="remote-http-error") as captured:
            await transport.request_json(_request())
        rendered = f"{captured.value!s} {captured.value!r}"
        assert "synthetic-secret" not in rendered
        assert "private body" not in rendered

    asyncio.run(scenario())


def test_timeout_is_sanitized_and_closes_no_cross_provider_retry_path() -> None:
    calls = 0

    async def connect(host: str, port: int, ssl_context: object, server_hostname: str):
        nonlocal calls
        calls += 1
        await asyncio.sleep(1)
        raise AssertionError("unreachable")

    async def scenario() -> None:
        transport = RemoteHttpsTransport(
            RemoteTransportSettings(timeout_seconds=0.01),
            connector=cast(Connector, connect),
        )
        with pytest.raises(RemoteTransportError, match="remote-timeout"):
            await transport.request_json(_request())

    asyncio.run(scenario())
    assert calls == 1


def test_cancellation_propagates_without_becoming_provider_failure() -> None:
    entered = asyncio.Event()

    async def connect(host: str, port: int, ssl_context: object, server_hostname: str):
        entered.set()
        await asyncio.Future()
        raise AssertionError("unreachable")

    async def scenario() -> None:
        transport = RemoteHttpsTransport(
            RemoteTransportSettings(timeout_seconds=10.0),
            connector=cast(Connector, connect),
        )
        task = asyncio.create_task(transport.request_json(_request()))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
