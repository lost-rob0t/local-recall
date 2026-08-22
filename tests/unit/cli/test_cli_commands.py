from dataclasses import dataclass, field, replace

from typer.testing import CliRunner

from local_recall.cli import app, set_client_factory
from local_recall.cli_contract import CliLifecycleState, CliOutcome, CliRequest, CliResponse
from local_recall.cli_service import DaemonClient

runner = CliRunner()


def _requests() -> list[CliRequest]:
    return []


@dataclass
class FakeClient(DaemonClient):
    response: CliResponse
    requests: list[CliRequest] = field(default_factory=_requests)

    def request(self, request: CliRequest) -> CliResponse:
        self.requests.append(request)
        return replace(self.response, request_id=request.request_id)


def test_status_uses_authoritative_daemon_state() -> None:
    client = FakeClient(
        CliResponse.success(request_id="placeholder", lifecycle_state=CliLifecycleState.RECORDING)
    )
    set_client_factory(lambda: client)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    assert "recording" in result.stdout
    assert "xorg" not in result.stdout.lower()
    assert len(client.requests) == 1
    assert client.requests[0].command.value == "status"


def test_stop_only_succeeds_after_daemon_confirms_off() -> None:
    client = FakeClient(
        CliResponse.success(request_id="placeholder", lifecycle_state=CliLifecycleState.OFF)
    )
    set_client_factory(lambda: client)

    result = runner.invoke(app, ["stop"])

    assert result.exit_code == 0
    assert "off" in result.stdout
    assert client.requests[0].priority.value == "urgent-control"


def test_unavailable_daemon_has_stable_nonzero_exit() -> None:
    client = FakeClient(
        CliResponse.failure(
            request_id="placeholder",
            outcome=CliOutcome.UNAVAILABLE,
            reason_code="daemon-unavailable",
        )
    )
    set_client_factory(lambda: client)

    result = runner.invoke(app, ["start"])

    assert result.exit_code == 3
    assert "daemon-unavailable" in result.stdout


def test_privacy_command_is_urgent_control() -> None:
    client = FakeClient(
        CliResponse.success(request_id="placeholder", lifecycle_state=CliLifecycleState.PAUSED)
    )
    set_client_factory(lambda: client)

    result = runner.invoke(app, ["privacy-on"])

    assert result.exit_code == 0
    assert client.requests[0].priority.value == "urgent-control"


def test_static_completion_does_not_construct_daemon_client() -> None:
    marker = "synthetic-completion-private-marker"

    def forbidden_factory() -> DaemonClient:
        raise AssertionError(marker)

    set_client_factory(forbidden_factory)
    result = runner.invoke(app, ["--show-completion", "bash"])

    assert result.exit_code == 0
    assert marker not in result.stdout
    assert "status" in result.stdout
