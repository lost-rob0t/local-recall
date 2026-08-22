import datetime as dt
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

import pytest

from local_recall.cli_contract import (
    CliCommand,
    CliLifecycleState,
    CliOutcome,
    CliRequest,
    CliResponse,
)
from local_recall.cli_service import DaemonClient, execute_command, exit_code_for


def _requests() -> list[CliRequest]:
    return []


@dataclass
class FakeClient(DaemonClient):
    response: CliResponse
    requests: list[CliRequest] = field(default_factory=_requests)

    def request(self, request: CliRequest) -> CliResponse:
        self.requests.append(request)
        return replace(self.response, request_id=request.request_id)


def test_exit_codes_are_stable_by_outcome() -> None:
    assert exit_code_for(CliOutcome.SUCCESS) == 0
    assert exit_code_for(CliOutcome.INVALID) == 2
    assert exit_code_for(CliOutcome.UNAVAILABLE) == 3
    assert exit_code_for(CliOutcome.TIMEOUT) == 3
    assert exit_code_for(CliOutcome.OVERLOADED) == 3
    assert exit_code_for(CliOutcome.UNAUTHORIZED) == 4
    assert exit_code_for(CliOutcome.LOCKED) == 4
    assert exit_code_for(CliOutcome.FAULTED) == 5
    assert exit_code_for(CliOutcome.INTERNAL_FAILURE) == 5
    assert exit_code_for(CliOutcome.CANCELLED) == 130


def test_execute_uses_daemon_client_and_preserves_priority() -> None:
    client = FakeClient(CliResponse.success(request_id="placeholder", lifecycle_state="paused"))
    now = dt.datetime(2026, 8, 22, 20, 0, tzinfo=dt.UTC)

    result = execute_command(
        client=client,
        command=CliCommand.PRIVACY_ON,
        now=now,
        timeout=dt.timedelta(seconds=2),
    )

    assert result.exit_code == 0
    assert len(client.requests) == 1
    request = client.requests[0]
    assert request.command is CliCommand.PRIVACY_ON
    assert request.priority.value == "urgent-control"


def test_stop_success_requires_authoritative_off_state() -> None:
    client = FakeClient(CliResponse.success(request_id="placeholder", lifecycle_state="recording"))
    now = dt.datetime(2026, 8, 22, 20, 0, tzinfo=dt.UTC)

    result = execute_command(
        client=client,
        command=CliCommand.STOP,
        now=now,
        timeout=dt.timedelta(seconds=2),
    )

    assert result.exit_code == 5
    assert result.response.outcome is CliOutcome.INTERNAL_FAILURE
    assert result.response.reason_code == "stop-not-quiescent"


@pytest.mark.parametrize(
    "command",
    [
        CliCommand.START,
        CliCommand.PAUSE,
        CliCommand.RESUME,
        CliCommand.STATUS,
        CliCommand.PRIVACY_ON,
        CliCommand.PRIVACY_OFF,
    ],
)
def test_lifecycle_success_requires_authoritative_state(command: CliCommand) -> None:
    client = FakeClient(CliResponse.success(request_id="placeholder"))
    now = dt.datetime(2026, 8, 22, 20, 0, tzinfo=dt.UTC)

    result = execute_command(
        client=client,
        command=command,
        now=now,
        timeout=dt.timedelta(seconds=2),
    )

    assert result.exit_code == 5
    assert result.response.outcome is CliOutcome.INTERNAL_FAILURE
    assert result.response.reason_code == "lifecycle-state-missing"


def test_concurrent_control_requests_remain_independent() -> None:
    requests: list[CliRequest] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    class ConcurrentClient(DaemonClient):
        def request(self, request: CliRequest) -> CliResponse:
            barrier.wait(timeout=1)
            with lock:
                requests.append(request)
            state = (
                CliLifecycleState.OFF
                if request.command is CliCommand.STOP
                else CliLifecycleState.PAUSED
            )
            return CliResponse.success(request_id=request.request_id, lifecycle_state=state)

    now = dt.datetime(2026, 8, 22, 20, 0, tzinfo=dt.UTC)

    def invoke(command: CliCommand) -> tuple[int, str]:
        result = execute_command(
            client=ConcurrentClient(),
            command=command,
            now=now,
            timeout=dt.timedelta(seconds=2),
        )
        return result.exit_code, result.response.request_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        stop_future = executor.submit(invoke, CliCommand.STOP)
        pause_future = executor.submit(invoke, CliCommand.PAUSE)
        stop_result = stop_future.result(timeout=2)
        pause_result = pause_future.result(timeout=2)

    assert stop_result[0] == 0
    assert pause_result[0] == 0
    assert stop_result[1] != pause_result[1]
    assert {request.command for request in requests} == {CliCommand.STOP, CliCommand.PAUSE}
    assert (
        next(request for request in requests if request.command is CliCommand.STOP).priority.value
        == "urgent-control"
    )


def test_mismatched_response_id_fails_closed() -> None:
    class MismatchedClient(DaemonClient):
        def request(self, request: CliRequest) -> CliResponse:
            del request
            return CliResponse.success(request_id="wrong-request", lifecycle_state="paused")

    now = dt.datetime(2026, 8, 22, 20, 0, tzinfo=dt.UTC)
    result = execute_command(
        client=MismatchedClient(),
        command=CliCommand.STATUS,
        now=now,
        timeout=dt.timedelta(seconds=2),
    )

    assert result.exit_code == 5
    assert result.response.reason_code == "request-mismatch"


def test_failure_result_does_not_expose_client_exception_text() -> None:
    class ExplodingClient(DaemonClient):
        def request(self, request: CliRequest) -> CliResponse:
            del request
            raise RuntimeError("synthetic-private-exception-marker")

    now = dt.datetime(2026, 8, 22, 20, 0, tzinfo=dt.UTC)
    result = execute_command(
        client=ExplodingClient(),
        command=CliCommand.STATUS,
        now=now,
        timeout=dt.timedelta(seconds=2),
    )

    assert result.exit_code == 5
    assert result.response.reason_code == "client-failure"
    assert "synthetic-private-exception-marker" not in repr(result)
    assert "synthetic-private-exception-marker" not in result.response.to_json()
