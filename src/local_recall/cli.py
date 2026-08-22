"""Command-line entry point for Local Recall."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from local_recall import __version__
from local_recall.cli_contract import (
    CliCommand,
    CliDiagnosticPayload,
    CliOutcome,
    CliQueryPayload,
    CliRequest,
    CliResponse,
)
from local_recall.cli_service import DaemonClient, execute_command
from local_recall.config import ConfigurationError, load_configuration_file

app = typer.Typer(
    name="local-recall",
    help="Local-first encrypted desktop activity recall.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Validate Local Recall configuration.")
storage_app = typer.Typer(help="Inspect Local Recall storage status.")
app.add_typer(config_app, name="config")
app.add_typer(storage_app, name="storage")

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


def _render_query_payload(payload: CliQueryPayload) -> str:
    lines = [payload.text]
    lines.extend(
        f"[{citation.record_id} @ {citation.captured_at.isoformat()}]"
        for citation in payload.citations
    )
    return "\n".join(lines)


def _render_diagnostic_payload(payload: CliDiagnosticPayload) -> str:
    lines = [payload.category.value]
    for entry in payload.entries:
        suffix = f" ({entry.value})" if entry.value is not None else ""
        lines.append(f"{entry.name}: {entry.state}{suffix}")
    return "\n".join(lines)


def _parse_query_bound(value: str | None, *, name: str) -> dt.datetime | None:
    if value is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise typer.BadParameter(f"{name} must be ISO-8601 with a timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise typer.BadParameter(f"{name} must include a timezone")
    return parsed


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


def _run_query_command(
    command: CliCommand,
    *,
    query: str | None,
    start: str | None,
    end: str | None,
    json_output: bool,
) -> None:
    if (start is None) is not (end is None):
        raise typer.BadParameter("start and end must be supplied together")
    parsed_start = _parse_query_bound(start, name="start")
    parsed_end = _parse_query_bound(end, name="end")

    now = dt.datetime.now(dt.UTC)
    result = execute_command(
        client=_client_factory(),
        command=command,
        now=now,
        timeout=_DEFAULT_TIMEOUT,
        query=query,
        start=parsed_start,
        end=parsed_end,
    )
    if result.exit_code != 0:
        typer.echo(_render_response(result.response))
        raise typer.Exit(result.exit_code)

    payload = result.response.query_payload
    if payload is None:
        typer.echo("query-result-missing")
        raise typer.Exit(5)
    typer.echo(payload.to_json() if json_output else _render_query_payload(payload))


def _run_diagnostic_command(command: CliCommand, *, json_output: bool) -> None:
    now = dt.datetime.now(dt.UTC)
    result = execute_command(
        client=_client_factory(),
        command=command,
        now=now,
        timeout=_DEFAULT_TIMEOUT,
    )
    if result.exit_code != 0:
        typer.echo(_render_response(result.response))
        raise typer.Exit(result.exit_code)

    payload = result.response.diagnostic_payload
    if payload is None:
        typer.echo("diagnostic-result-missing")
        raise typer.Exit(5)
    typer.echo(payload.to_json() if json_output else _render_diagnostic_payload(payload))


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


@app.command()
def ask(
    question: str,
    start: Annotated[str | None, typer.Option()] = None,
    end: Annotated[str | None, typer.Option()] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Ask a question over retained activity with citations."""
    _run_query_command(
        CliCommand.ASK,
        query=question,
        start=start,
        end=end,
        json_output=json_output,
    )


@app.command()
def search(
    query: str,
    start: Annotated[str | None, typer.Option()] = None,
    end: Annotated[str | None, typer.Option()] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Search retained activity with optional explicit time bounds."""
    _run_query_command(
        CliCommand.SEARCH,
        query=query,
        start=start,
        end=end,
        json_output=json_output,
    )


@app.command()
def timeline(
    start: Annotated[str | None, typer.Option()] = None,
    end: Annotated[str | None, typer.Option()] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Render a bounded activity timeline."""
    _run_query_command(
        CliCommand.TIMELINE,
        query=None,
        start=start,
        end=end,
        json_output=json_output,
    )


@app.command()
def providers(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show sanitized generation and embedding provider status."""
    _run_diagnostic_command(CliCommand.PROVIDERS, json_output=json_output)


@app.command()
def health(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show sanitized daemon health status."""
    _run_diagnostic_command(CliCommand.HEALTH, json_output=json_output)


@storage_app.command("stats")
def storage_stats(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show sanitized storage statistics."""
    _run_diagnostic_command(CliCommand.STORAGE_STATS, json_output=json_output)


@config_app.command("validate")
def config_validate(path: Path) -> None:
    """Validate one versioned configuration file without printing its values."""
    try:
        load_configuration_file(path, environ={})
    except ConfigurationError:
        typer.echo("invalid-configuration")
        raise typer.Exit(2) from None
    typer.echo("valid")
