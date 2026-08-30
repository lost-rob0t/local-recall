from __future__ import annotations

import http.client
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest
from local_recall.cli_contract import (
    CliCommand,
    CliLifecycleState,
    CliQueryPayload,
    CliRequest,
    CliResponse,
)
from local_recall.timeline.ui import TimelineUiServer

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_PREVIEW_MARKER = "preview-plaintext-secret-marker"


@dataclass
class FakeDaemonClient:
    responses: dict[str, CliResponse] = field(default_factory=dict)
    requests: list[CliRequest] = field(default_factory=list)

    def request(self, request: CliRequest) -> CliResponse:
        self.requests.append(request)
        return self.responses.get(
            request.command.value,
            CliResponse.success(
                request_id=request.request_id, lifecycle_state=CliLifecycleState.RECORDING
            ),
        )


def _client() -> FakeDaemonClient:
    client = FakeDaemonClient()
    client.responses = {
        "status": CliResponse.success(
            request_id="status", lifecycle_state=CliLifecycleState.RECORDING
        ),
        "preview-record": CliResponse.success(
            request_id="preview-record",
            lifecycle_state=CliLifecycleState.RECORDING,
            query_payload=CliQueryPayload(text=_PREVIEW_MARKER),
        ),
        "stop": CliResponse.success(request_id="stop", lifecycle_state=CliLifecycleState.RECORDING),
    }
    return client


@pytest.fixture()
def server(tmp_path: Path):
    client = _client()
    instance = TimelineUiServer(client=client, host="127.0.0.1", port=0, now=lambda: NOW)
    session = instance.start()
    yield instance, session.token, client
    if instance.is_running():
        instance.close()


def _get(server: TimelineUiServer, token: str, path: str) -> http.client.HTTPResponse:
    connection = http.client.HTTPConnection(server.host, server.port, timeout=5)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    connection.request("GET", path, headers=headers)
    return connection.getresponse()


def _post(
    server: TimelineUiServer, token: str, path: str, body: dict[str, object]
) -> http.client.HTTPResponse:
    connection = http.client.HTTPConnection(server.host, server.port, timeout=5)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    connection.request("POST", path, json.dumps(body), headers=headers)
    return connection.getresponse()


def _no_cache_headers(response: http.client.HTTPResponse) -> None:
    assert response.getheader("Cache-Control") == "no-store"
    assert response.getheader("Pragma") == "no-cache"


def test_every_response_forbids_browser_caching(server) -> None:
    instance, token, _client = server
    responses = [
        _get(instance, "", "/"),
        _get(instance, token, "/api/status"),
        _get(instance, token, "/api/preview/c0ffee00-0000-4000-8000-000000000001"),
    ]
    for response in responses:
        _no_cache_headers(response)


def test_preview_marker_is_never_persisted_or_retained(server, tmp_path: Path) -> None:
    instance, token, _client = server
    response = _get(instance, token, "/api/preview/c0ffee00-0000-4000-8000-000000000001")
    body = response.read()
    assert _PREVIEW_MARKER.encode() in body
    assert instance.cached_previews() == 0
    for path in Path(tmp_path).rglob("*"):
        if path.is_file():
            assert _PREVIEW_MARKER.encode() not in path.read_bytes()


def test_ui_asset_contains_no_external_urls(server) -> None:
    instance, _token, _client = server
    shell = instance.page_source()
    assert not re.search(r"https?://", shell)
    assert "<script src=" not in shell
    assert "<link " not in shell


def test_emergency_stop_is_keyboard_accessible(server) -> None:
    instance, _token, client = server
    shell = instance.page_source()
    assert 'accesskey="s"' in shell
    assert "keydown" in shell
    response = _post(instance, server[1], "/api/stop", {})
    assert response.status == 200
    assert client.requests[-1].command is CliCommand.STOP


def test_session_close_clears_credentials_and_previews(server) -> None:
    instance, token, _client = server
    _get(instance, token, "/api/preview/c0ffee00-0000-4000-8000-000000000001")
    close = _post(instance, token, "/api/session/close", {})
    assert close.status == 200
    assert instance.cached_previews() == 0
    assert instance.session_token_active(token) is False
    assert instance.is_running() is False


def test_expired_session_clears_credentials(server) -> None:
    current = {"value": NOW}
    client = _client()
    instance = TimelineUiServer(
        client=client,
        host="127.0.0.1",
        port=0,
        now=lambda: current["value"],
        session_timeout_seconds=30,
    )
    session = instance.start()
    try:
        from datetime import timedelta as _timedelta

        current["value"] = NOW + _timedelta(seconds=31)
        assert _get(instance, session.token, "/api/status").status == 401
        assert instance.session_token_active(session.token) is False
    finally:
        if instance.is_running():
            instance.close()


def test_server_binds_loopback_only(server) -> None:
    instance, _token, _client = server
    assert instance.host == "127.0.0.1"
