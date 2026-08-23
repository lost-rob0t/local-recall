import datetime as dt
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from local_recall import cli, ipc_transport
from local_recall.cli import app, set_client_factory
from local_recall.cli_contract import (
    CliCitation,
    CliDiagnosticCategory,
    CliDiagnosticEntry,
    CliDiagnosticPayload,
    CliLifecycleState,
    CliOutcome,
    CliQueryPayload,
    CliRequest,
    CliResponse,
)
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
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["status"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert "recording" in result.stdout
    assert "xorg" not in result.stdout.lower()
    assert len(client.requests) == 1
    assert client.requests[0].command.value == "status"


def test_stop_only_succeeds_after_daemon_confirms_off() -> None:
    client = FakeClient(
        CliResponse.success(request_id="placeholder", lifecycle_state=CliLifecycleState.OFF)
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["stop"])
    finally:
        set_client_factory(previous)

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
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["start"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 3
    assert "daemon-unavailable" in result.stdout


def test_privacy_command_is_urgent_control() -> None:
    client = FakeClient(
        CliResponse.success(request_id="placeholder", lifecycle_state=CliLifecycleState.PAUSED)
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["privacy-on"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert client.requests[0].priority.value == "urgent-control"


def test_ask_sends_question_and_renders_citations() -> None:
    citation = CliCitation(
        record_id="record-1",
        captured_at=dt.datetime(2026, 8, 16, 14, 30, tzinfo=dt.UTC),
    )
    client = FakeClient(
        CliResponse.success(
            request_id="placeholder",
            query_payload=CliQueryPayload(
                text="You were reviewing Local Recall.",
                citations=(citation,),
            ),
        )
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["ask", "What was I doing Saturday?"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert "You were reviewing Local Recall." in result.stdout
    assert "record-1" in result.stdout
    assert "2026-08-16T14:30:00+00:00" in result.stdout
    assert client.requests[0].query == "What was I doing Saturday?"
    assert client.requests[0].command.value == "ask"


def test_ask_json_renders_machine_payload() -> None:
    client = FakeClient(
        CliResponse.success(
            request_id="placeholder",
            query_payload=CliQueryPayload(text="summary"),
        )
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["ask", "question", "--json"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert result.stdout.strip() == '{"citations":[],"text":"summary"}'


def test_search_passes_explicit_time_filter() -> None:
    client = FakeClient(
        CliResponse.success(
            request_id="placeholder",
            query_payload=CliQueryPayload(text="match"),
        )
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(
            app,
            [
                "search",
                "work",
                "--start",
                "2026-08-16T00:00:00+00:00",
                "--end",
                "2026-08-17T00:00:00+00:00",
            ],
        )
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert client.requests[0].query == "work"
    assert client.requests[0].start == dt.datetime(2026, 8, 16, 0, 0, tzinfo=dt.UTC)
    assert client.requests[0].end == dt.datetime(2026, 8, 17, 0, 0, tzinfo=dt.UTC)


def test_timeline_requires_both_time_filter_bounds() -> None:
    previous = set_client_factory(
        lambda: FakeClient(
            CliResponse.success(
                request_id="placeholder",
                query_payload=CliQueryPayload(text="timeline"),
            )
        )
    )
    try:
        result = runner.invoke(
            app,
            ["timeline", "--start", "2026-08-16T00:00:00+00:00"],
        )
    finally:
        set_client_factory(previous)

    assert result.exit_code == 2


def test_locked_query_has_stable_nonzero_exit() -> None:
    client = FakeClient(
        CliResponse.failure(
            request_id="placeholder",
            outcome=CliOutcome.LOCKED,
            reason_code="key-store-locked",
        )
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["ask", "question"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 4
    assert "key-store-locked" in result.stdout


def test_providers_json_renders_typed_diagnostics() -> None:
    client = FakeClient(
        CliResponse.success(
            request_id="placeholder",
            diagnostic_payload=CliDiagnosticPayload(
                category=CliDiagnosticCategory.PROVIDERS,
                entries=(CliDiagnosticEntry(name="ollama", state="available", value="local"),),
            ),
        )
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["providers", "--json"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert result.stdout.strip() == (
        '{"category":"providers","entries":[{"name":"ollama","state":"available","value":"local"}]}'
    )
    assert client.requests[0].command.value == "providers"


def test_health_renders_human_diagnostics() -> None:
    client = FakeClient(
        CliResponse.success(
            request_id="placeholder",
            diagnostic_payload=CliDiagnosticPayload(
                category=CliDiagnosticCategory.HEALTH,
                entries=(CliDiagnosticEntry(name="daemon", state="ok"),),
            ),
        )
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["health"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert "daemon: ok" in result.stdout
    assert client.requests[0].command.value == "health"


def test_storage_stats_is_nested_and_machine_readable() -> None:
    client = FakeClient(
        CliResponse.success(
            request_id="placeholder",
            diagnostic_payload=CliDiagnosticPayload(
                category=CliDiagnosticCategory.STORAGE,
                entries=(CliDiagnosticEntry(name="records", state="ok", value="42"),),
            ),
        )
    )
    previous = set_client_factory(lambda: client)
    try:
        result = runner.invoke(app, ["storage", "stats", "--json"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert '"category":"storage"' in result.stdout
    assert '"value":"42"' in result.stdout
    assert client.requests[0].command.value == "storage-stats"


def test_config_validate_accepts_versioned_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('schema_version = 1\nprofile = "privacy-strict"\n', encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", str(path)])

    assert result.exit_code == 0
    assert result.stdout.strip() == "valid"


def test_config_validate_failure_is_content_free(tmp_path: Path) -> None:
    marker = "VALUE-MUST-NOT-APPEAR"
    path = tmp_path / "config.toml"
    path.write_text(f'schema_version = 1\nprofile = "{marker}"\n', encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", str(path)])

    assert result.exit_code == 2
    assert "invalid-configuration" in result.stdout
    assert marker not in result.stdout


def test_static_completion_does_not_construct_daemon_client() -> None:
    marker = "synthetic-completion-private-marker"

    def forbidden_factory() -> DaemonClient:
        raise AssertionError(marker)

    previous = set_client_factory(forbidden_factory)
    try:
        result = runner.invoke(app, ["--show-completion", "bash"])
    finally:
        set_client_factory(previous)

    assert result.exit_code == 0
    assert marker not in result.stdout
    assert "LOCAL_RECALL_COMPLETE" in result.stdout


def test_default_cli_client_uses_authenticated_runtime_ipc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    runtime_dir.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))

    client = cli._default_client_factory()

    assert isinstance(client, ipc_transport.ZmqDaemonClient)
    assert str(runtime_dir) not in repr(client)
