from __future__ import annotations

import asyncio
from collections.abc import Mapping
from importlib import import_module
from typing import cast

import pytest

remote = import_module("local_recall.providers.remote")
executor_module = import_module("local_recall.providers.remote_executor")

RemoteHttpRequest = remote.RemoteHttpRequest
RemoteTransportError = remote.RemoteTransportError
RemoteExecutionSettings = executor_module.RemoteExecutionSettings
RemoteRequestExecutor = executor_module.RemoteRequestExecutor


def _request() -> object:
    return RemoteHttpRequest(
        method="POST",
        origin="https://api.example.test",
        path="/v1/messages",
        headers={"authorization": "Bearer synthetic-secret"},
        body=b'{"safe":"payload"}',
    )


class FakeTransport:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[object] = []

    async def request_json(self, request: object) -> Mapping[str, object]:
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, dict)
        return cast(Mapping[str, object], outcome)


def test_transient_failure_retries_same_immutable_request_only() -> None:
    request = _request()
    transport = FakeTransport([RemoteTransportError("remote-timeout"), {"ok": True}])

    async def scenario() -> None:
        executor = RemoteRequestExecutor(
            transport,
            RemoteExecutionSettings(max_attempts=2, deadline_seconds=1.0),
        )
        response = await executor.execute(request)
        assert response == {"ok": True}

    asyncio.run(scenario())
    assert transport.requests == [request, request]


def test_non_transient_provider_error_is_not_retried() -> None:
    request = _request()
    transport = FakeTransport([RemoteTransportError("remote-http-error")])

    async def scenario() -> None:
        executor = RemoteRequestExecutor(
            transport,
            RemoteExecutionSettings(max_attempts=3, deadline_seconds=1.0),
        )
        with pytest.raises(RemoteTransportError, match="remote-http-error"):
            await executor.execute(request)

    asyncio.run(scenario())
    assert transport.requests == [request]


def test_retry_budget_exhaustion_preserves_sanitized_transport_failure() -> None:
    request = _request()
    transport = FakeTransport(
        [
            RemoteTransportError("remote-connection-failed"),
            RemoteTransportError("remote-connection-failed"),
        ]
    )

    async def scenario() -> None:
        executor = RemoteRequestExecutor(
            transport,
            RemoteExecutionSettings(max_attempts=2, deadline_seconds=1.0),
        )
        with pytest.raises(RemoteTransportError, match="remote-connection-failed"):
            await executor.execute(request)

    asyncio.run(scenario())
    assert transport.requests == [request, request]


def test_cancellation_propagates_without_retry() -> None:
    request = _request()

    class CancellingTransport(FakeTransport):
        async def request_json(self, request: object) -> Mapping[str, object]:
            self.requests.append(request)
            raise asyncio.CancelledError

    transport = CancellingTransport([])

    async def scenario() -> None:
        executor = RemoteRequestExecutor(
            transport,
            RemoteExecutionSettings(max_attempts=3, deadline_seconds=1.0),
        )
        with pytest.raises(asyncio.CancelledError):
            await executor.execute(request)

    asyncio.run(scenario())
    assert transport.requests == [request]


def test_overall_deadline_bounds_all_attempts() -> None:
    request = _request()

    class SlowTransport(FakeTransport):
        async def request_json(self, request: object) -> Mapping[str, object]:
            self.requests.append(request)
            await asyncio.sleep(1)
            return {"unreachable": True}

    transport = SlowTransport([])

    async def scenario() -> None:
        executor = RemoteRequestExecutor(
            transport,
            RemoteExecutionSettings(max_attempts=3, deadline_seconds=0.01),
        )
        with pytest.raises(RemoteTransportError, match="remote-deadline-exceeded"):
            await executor.execute(request)

    asyncio.run(scenario())
    assert transport.requests == [request]
