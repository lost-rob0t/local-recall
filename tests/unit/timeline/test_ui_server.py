from __future__ import annotations

import http.client
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from local_recall.cli_contract import (
    CliCitation,
    CliCommand,
    CliDeletionPayload,
    CliLifecycleState,
    CliOutcome,
    CliQueryPayload,
    CliRequest,
    CliResponse,
    CliStatusPayload,
)
from local_recall.timeline.ui import TimelineUiServer

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


@dataclass
class FakeDaemonClient:
    responses: dict[str, CliResponse] = field(default_factory=dict[str, CliResponse])
    requests: list[CliRequest] = field(default_factory=list[CliRequest])

    def request(self, request: CliRequest) -> CliResponse:
        self.requests.append(request)
        return self.responses.get(request.command.value, _success(request.request_id))


def _success(request_id: str) -> CliResponse:
    return CliResponse.success(request_id=request_id, lifecycle_state=CliLifecycleState.RECORDING)


def _query_response(request_id: str, text: str) -> CliResponse:
    citation = ("c0ffee00-0000-4000-8000-000000000001", NOW - timedelta(hours=1))
    return CliResponse.success(
        request_id=request_id,
        lifecycle_state=CliLifecycleState.RECORDING,
        query_payload=CliQueryPayload(
            text=text,
            citations=tuple(
                CliCitation(record_id=item[0], captured_at=item[1]) for item in [citation]
            ),
        ),
    )


def _client() -> FakeDaemonClient:
    client = FakeDaemonClient()
    client.responses = {
        "status": CliResponse.success(
            request_id="status",
            lifecycle_state=CliLifecycleState.RECORDING,
            status_payload=CliStatusPayload(privacy_mode=False, capture_backend="xorg"),
        ),
        "ask": _query_response("ask", "Worked on the roadmap."),
        "search": _query_response("search", "two hits"),
        "timeline": _query_response("timeline", "[]"),
        "preview-record": _query_response("preview-record", "preview-text"),
        "delete-records": CliResponse.success(
            request_id="delete-records",
            lifecycle_state=CliLifecycleState.RECORDING,
            deletion_payload=CliDeletionPayload(deleted_count=1, scope_kind="record-ids"),
        ),
    }
    return client


@pytest.fixture()
def server(tmp_path: Path):
    client = _client()
    instance = TimelineUiServer(client=client, host="127.0.0.1", port=0, now=lambda: NOW)
    session = instance.start()
    yield instance, session.token, client
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


def test_root_page_is_served_without_token(server) -> None:
    instance, _token, _client = server
    response = _get(instance, "", "/")
    assert response.status == 200
    assert b"local recall" in response.read().lower()


def test_api_requires_bearer_token(server) -> None:
    instance, token, _client = server
    assert _get(instance, "", "/api/status").status == 401
    assert _get(instance, "wrong-token", "/api/status").status == 401
    assert _get(instance, token, "/api/status").status == 200


def test_status_maps_to_daemon_status_command(server) -> None:
    instance, token, client = server
    response = _get(instance, token, "/api/status")
    assert response.status == 200
    document = json.loads(response.read())
    assert document["state"] == "recording"
    assert client.requests[-1].command is CliCommand.STATUS


def test_timeline_maps_to_daemon_timeline_command(server) -> None:
    instance, token, client = server
    response = _get(
        instance,
        token,
        "/api/timeline?start=2026-08-30T00:00:00%2B00:00&end=2026-08-30T12:00:00%2B00:00",
    )
    assert response.status == 200
    assert client.requests[-1].command is CliCommand.TIMELINE


def test_search_maps_to_daemon_search_command(server) -> None:
    instance, token, client = server
    response = _get(instance, token, "/api/search?q=roadmap")
    assert response.status == 200
    assert client.requests[-1].command is CliCommand.SEARCH


def test_answer_is_local_only_without_explicit_remote_confirmation(server) -> None:
    instance, token, client = server
    response = _post(instance, token, "/api/answer", {"question": "What was I doing today?"})
    assert response.status == 200
    request = client.requests[-1]
    assert request.command is CliCommand.ASK
    assert request.query == "What was I doing today?"


def test_answer_requires_explicit_remote_confirmation(server) -> None:
    instance, token, client = server
    response = _post(
        instance,
        token,
        "/api/answer",
        {"question": "What was I doing today?", "confirm_remote": True},
    )
    assert response.status == 200
    assert client.requests[-1].command is CliCommand.ASK


def test_answer_rejects_missing_question(server) -> None:
    instance, token, _client = server
    response = _post(instance, token, "/api/answer", {})
    assert response.status == 400


def test_preview_is_decrypt_on_demand_and_not_cached(server) -> None:
    instance, token, client = server
    record_id = "c0ffee00-0000-4000-8000-000000000001"
    response = _get(instance, token, f"/api/preview/{record_id}")
    assert response.status == 200
    body = response.read()
    assert b"preview-text" in body
    assert client.requests[-1].command is CliCommand.PREVIEW_RECORD
    assert client.requests[-1].record_ids == (record_id,)
    assert instance.cached_previews() == 0
    assert response.getheader("Cache-Control") == "no-store"


def test_delete_requires_confirmation_and_shows_exact_scope(server) -> None:
    instance, token, client = server
    record_id = "c0ffee00-0000-4000-8000-000000000001"

    refused = _post(instance, token, "/api/delete", {"record_ids": [record_id]})
    assert refused.status == 400
    assert all(request.command is not CliCommand.DELETE_RECORDS for request in client.requests)

    confirmed = _post(
        instance,
        token,
        "/api/delete",
        {"record_ids": [record_id], "confirm": True},
    )
    assert confirmed.status == 200
    document = json.loads(confirmed.read())
    assert document["deleted_count"] == 1
    assert document["scope_kind"] == "record-ids"
    assert client.requests[-1].command is CliCommand.DELETE_RECORDS
    assert client.requests[-1].record_ids == (record_id,)


def test_emergency_stop_maps_to_daemon_stop(server) -> None:
    instance, token, client = server
    response = _post(instance, token, "/api/stop", {})
    assert response.status == 200
    assert client.requests[-1].command is CliCommand.STOP


def test_privacy_controls_map_to_daemon_commands(server) -> None:
    instance, token, client = server
    assert _post(instance, token, "/api/privacy-on", {}).status == 200
    assert client.requests[-1].command is CliCommand.PRIVACY_ON
    assert _post(instance, token, "/api/privacy-off", {}).status == 200
    assert client.requests[-1].command is CliCommand.PRIVACY_OFF


def test_daemon_failure_maps_to_error_status(server) -> None:
    client = FakeDaemonClient()
    client.responses = {
        "status": CliResponse.failure(
            request_id="status", outcome=CliOutcome.UNAVAILABLE, reason_code="daemon-unavailable"
        )
    }
    instance = TimelineUiServer(client=client, host="127.0.0.1", port=0, now=lambda: NOW)
    session = instance.start()
    try:
        response = _get(instance, session.token, "/api/status")
        assert response.status == 503
        document = json.loads(response.read())
        assert document["reason_code"] == "daemon-unavailable"
    finally:
        instance.close()


def test_session_close_invalidates_token_and_shuts_down(server) -> None:
    instance, token, _client = server
    response = _post(instance, token, "/api/session/close", {})
    assert response.status == 200
    assert instance.is_running() is False
    assert _get(instance, token, "/api/status").status in (401,)


def test_inactive_session_expires(server) -> None:
    current = {"value": NOW}
    client = _client()
    instance = TimelineUiServer(
        client=client,
        host="127.0.0.1",
        port=0,
        now=lambda: current["value"],
        session_timeout_seconds=60,
    )
    session = instance.start()
    try:
        assert _get(instance, session.token, "/api/status").status == 200
        current["value"] = NOW + timedelta(seconds=61)
        assert _get(instance, session.token, "/api/status").status == 401
        assert instance.is_running() is False
    finally:
        if instance.is_running():
            instance.close()
