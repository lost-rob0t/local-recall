import datetime as dt
from dataclasses import dataclass, field, replace

from local_recall.cli_contract import CliCommand, CliOutcome, CliRequest, CliResponse
from local_recall.cli_service import DaemonClient, execute_command, exit_code_for


@dataclass
class FakeClient(DaemonClient):
    response: CliResponse
    requests: list[CliRequest] = field(default_factory=list)

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
    client = FakeClient(
        CliResponse.success(request_id="placeholder", lifecycle_state="paused")
    )
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
    client = FakeClient(
        CliResponse.success(request_id="placeholder", lifecycle_state="recording")
    )
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
