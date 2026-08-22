"""Command-line entry point for Local Recall."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable

import typer

from local_recall import __version__
from local_recall.cli_contract import CliCommand, CliOutcome, CliRequest, CliResponse
from local_recall.cli_service import DaemonClient, execute_command

app = typer.Typer(
    name="local-recall",
    help="Local-first encrypted desktop activity recall.",
    no_args_is_help=True,
)

ClientFactory = Callable[[], DaemonClient]
_DEFAULT_TIMEOUT = dt.timedelta(seconds=2)


class _UnavailableDaemonClient:
    """Fail-closed placeholder until authenticated daemon IPC lands in #29."""

    def request(self, request: CliRequest) -> CliResponse:
        return CliResponse.failure(
            request_id=request.request_id,
            outcome=CliOutcome.UNAVAILABLE,
            reason_code="daemon-unavailable",
        )


def _default_client_factory() -> DaemonClient:
    return _UnavailableDaemonClient()


_client_factory: ClientFactory = _default_client_factory


def set_client_factory(factory: ClientFactory) -> ClientFactory:
    """Replace the daemon client factory and return the prior factory."""
    global _client_factory
    previous = _client_factory
    _client_factory = factory
    return previous


def _render_response(response: CliResponse) -> str:
    if response.outcome is CliOutcome.SUCCESS:
        if response.lifecycle_state is not None:
            return response.lifecycle_state.value
        return response.outcome.value
    return response.reason_code or response.outcome.value


def _run_daemon_command(command: CliCommand) -> None:
    now = dt.datetime.now(dt.UTC)
    result = execute_command(
        client=_client_factory(),
        command=command,
        now=now,
        timeout=_DEFAULT_TIMEOUT,
    )
    typer.echo(_render_response(result.response))
    if result.exit_code != 0:
        raise typer.Exit(result.exit_code)


@app.callback()
def main() -> None:
    """Local Recall command group."""


@app.command()
def version() -> None:
    """Print the installed Local Recall version."""
    typer.echo(__version__)


@app.command()
def start() -> None:
    """Request recording start from the authoritative daemon."""
    _run_daemon_command(CliCommand.START)


@app.command()
def pause() -> None:
    """Request capture pause from the authoritative daemon."""
    _run_daemon_command(CliCommand.PAUSE)


@app.command()
def resume() -> None:
    """Request capture resume from the authoritative daemon."""
    _run_daemon_command(CliCommand.RESUME)


@app.command()
def stop() -> None:
    """Request a bounded stop and wait for authoritative quiescence."""
    _run_daemon_command(CliCommand.STOP)


@app.command()
def status() -> None:
    """Print the authoritative daemon lifecycle state."""
    _run_daemon_command(CliCommand.STATUS)


@app.command("privacy-on")
def privacy_on() -> None:
    """Enable immediate privacy mode through the daemon."""
    _run_daemon_command(CliCommand.PRIVACY_ON)


@app.command("privacy-off")
def privacy_off() -> None:
    """Disable privacy mode through the daemon."""
    _run_daemon_command(CliCommand.PRIVACY_OFF)
