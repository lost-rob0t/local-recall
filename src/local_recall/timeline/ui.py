"""Local-only timeline UI served over an explicitly-enabled loopback endpoint."""

from __future__ import annotations

import http.server
import json
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import cast
from urllib.parse import parse_qs, urlparse

from local_recall.cli_contract import CliCommand, CliOutcome, CliResponse
from local_recall.cli_service import DaemonClient, execute_command

_MAX_BODY_BYTES = 16 * 1024
_DEFAULT_SESSION_TIMEOUT = 300.0
_REQUEST_TIMEOUT = 5.0

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Recall</title>
<style>
:root { color-scheme: dark; }
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 52rem; padding: 0 1rem; }
button { padding: 0.4rem 0.9rem; }
.danger { border: 2px solid #b00; font-weight: bold; }
pre { white-space: pre-wrap; }
</style>
</head>
<body>
<h1>Local Recall</h1>
<section id="controls">
  <button id="stop" class="danger" accesskey="s">Emergency stop</button>
  <button id="privacy-on">Privacy on</button>
  <button id="privacy-off">Privacy off</button>
  <button id="close">Close session</button>
</section>
<section id="query">
  <label for="question">Question</label>
  <input id="question" name="question">
  <label><input type="checkbox" id="confirm-remote"> Allow remote processing this time</label>
  <button id="ask">Ask</button>
</section>
<section id="output"><pre id="result" aria-live="polite"></pre></section>
<script>
"use strict";
const out = (text) => { document.getElementById("result").textContent = text; };
const post = (path) => api(path, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: "{}",
});
const api = async (path, options) => {
  const response = await fetch(path, options);
  const text = await response.text();
  out(response.status + " " + text);
};
document.getElementById("stop").addEventListener("click", () => post("/api/stop"));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    post("/api/stop");
  }
});
document.getElementById("privacy-on").addEventListener("click", () => post("/api/privacy-on"));
document.getElementById("privacy-off").addEventListener("click", () => post("/api/privacy-off"));
document.getElementById("close").addEventListener("click", () => post("/api/session/close"));
document.getElementById("ask").addEventListener("click", () => {
  const question = document.getElementById("question").value;
  const confirmRemote = document.getElementById("confirm-remote").checked;
  api("/api/answer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question: question, confirm_remote: confirmRemote }),
  });
});
</script>
</body>
</html>
"""


class UiSessionError(RuntimeError):
    """Content-free UI session failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class UiSession:
    token: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class UiRequestContext:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str] = field(default_factory=dict[str, str])
    body: bytes = b""


class TimelineUiServer:
    """Loopback-only UI server; every API request requires the bearer token."""

    def __init__(
        self,
        *,
        client: DaemonClient,
        host: str = "127.0.0.1",
        port: int = 0,
        now: Callable[[], datetime] | None = None,
        token_factory: Callable[[], str] | None = None,
        session_timeout_seconds: float = _DEFAULT_SESSION_TIMEOUT,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("the timeline UI binds loopback only")
        if session_timeout_seconds <= 0 or session_timeout_seconds > 3600:
            raise ValueError("session timeout must be between 0 and 3600 seconds")
        self._client = client
        self._host = host
        self._port = port
        self._now = now or (lambda: datetime.now(UTC))
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._session_timeout = timedelta(seconds=session_timeout_seconds)
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._token: str | None = None
        self._last_seen: datetime | None = None
        self._retained_payloads = 0

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        if self._server is None:
            raise UiSessionError("ui-not-started")
        return self._server.server_address[1]

    def is_running(self) -> bool:
        return self._server is not None

    def cached_previews(self) -> int:
        return self._retained_payloads

    def session_token_active(self, token: str) -> bool:
        with self._lock:
            expected = self._token
            return expected is not None and secrets.compare_digest(token, expected)

    def start(self) -> UiSession:
        if self._server is not None:
            raise UiSessionError("ui-already-started")
        token = self._token_factory()
        server = _build_server(self, self._port)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        with self._lock:
            self._token = token
            self._last_seen = self._now()
        return UiSession(token=token, created_at=self._now())

    def close(self) -> None:
        server = self._server
        with self._lock:
            self._token = None
            self._last_seen = None
            self._retained_payloads = 0
        if server is not None:
            server.shutdown()
            server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def page_source(self) -> str:
        return _PAGE

    def authorize(self, token: str | None) -> None:
        with self._lock:
            expected = self._token
            now = self._now()
            if expected is None or token is None or not secrets.compare_digest(token, expected):
                raise UiSessionError("ui-unauthorized")
            if self._last_seen is None or now - self._last_seen > self._session_timeout:
                self._token = None
                self._last_seen = None
                raise UiSessionError("ui-session-expired")
            self._last_seen = now

    def handle(self, context: UiRequestContext) -> tuple[int, dict[str, str], bytes]:
        if context.path == "/" and context.method == "GET":
            return self._respond(
                HTTPStatus.OK, _PAGE.encode(), content_type="text/html; charset=utf-8"
            )
        try:
            self.authorize(_bearer(context.headers))
        except UiSessionError as error:
            if error.reason_code == "ui-session-expired":
                self.close()
            return self._respond(
                HTTPStatus.UNAUTHORIZED, json.dumps({"error": error.reason_code}).encode()
            )
        if context.method == "GET":
            return self._handle_get(context)
        if context.method == "POST":
            return self._handle_post(context)
        return self._respond(HTTPStatus.METHOD_NOT_ALLOWED, b'{"error":"method-not-allowed"}')

    def _handle_get(self, context: UiRequestContext) -> tuple[int, dict[str, str], bytes]:
        path = context.path
        if path == "/api/status":
            return self._command(CliCommand.STATUS)
        if path == "/api/timeline":
            return self._timeline_get(context)
        if path == "/api/search":
            return self._search_get(context)
        if path.startswith("/api/preview/"):
            return self._preview_get(context)

        return self._respond(HTTPStatus.NOT_FOUND, b'{"error":"not-found"}')

    def _handle_post(self, context: UiRequestContext) -> tuple[int, dict[str, str], bytes]:
        if len(context.body) > _MAX_BODY_BYTES:
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"body-too-large"}')
        try:
            parsed_body: object = json.loads(context.body.decode("utf-8")) if context.body else {}
        except ValueError:
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"invalid-json"}')
        if not isinstance(parsed_body, dict):
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"invalid-json"}')
        body = cast("dict[str, object]", parsed_body)
        if context.path == "/api/answer":
            return self._answer_post(body)
        if context.path == "/api/delete":
            return self._delete_post(body)
        if context.path == "/api/stop":
            return self._command(CliCommand.STOP)
        if context.path == "/api/privacy-on":
            return self._command(CliCommand.PRIVACY_ON)
        if context.path == "/api/privacy-off":
            return self._command(CliCommand.PRIVACY_OFF)
        if context.path == "/api/session/close":
            self.close()
            return self._respond(HTTPStatus.OK, b'{"closed": true}')
        return self._respond(HTTPStatus.NOT_FOUND, b'{"error":"not-found"}')

    def _timeline_get(self, context: UiRequestContext) -> tuple[int, dict[str, str], bytes]:
        values = context.query.get("start", [])
        ends = context.query.get("end", [])
        if not values or not ends:
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"timeline-requires-bounds"}')
        return self._command(
            CliCommand.TIMELINE,
            start=_parse_time(values[0]),
            end=_parse_time(ends[0]),
        )

    def _search_get(self, context: UiRequestContext) -> tuple[int, dict[str, str], bytes]:
        values = context.query.get("q", [])
        if not values or not values[0]:
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"search-requires-query"}')
        return self._command(CliCommand.SEARCH, query=values[0])

    def _preview_get(self, context: UiRequestContext) -> tuple[int, dict[str, str], bytes]:
        record_id = context.path.removeprefix("/api/preview/")
        if not _is_record_id(record_id):
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"invalid-record-id"}')
        targets = context.query.get("target", ["text"])
        target = targets[0]
        if target not in ("text", "image"):
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"invalid-preview-target"}')
        return self._command(CliCommand.PREVIEW_RECORD, record_ids=(record_id,), target=target)

    def _answer_post(self, body: dict[str, object]) -> tuple[int, dict[str, str], bytes]:
        question = body.get("question")
        if not isinstance(question, str) or not question:
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"question-required"}')
        return self._command(CliCommand.ASK, query=question)

    def _delete_post(self, body: dict[str, object]) -> tuple[int, dict[str, str], bytes]:
        record_ids = body.get("record_ids")
        confirm = body.get("confirm") is True
        if not isinstance(record_ids, list) or not record_ids:
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"scope-required"}')
        entries = cast("list[object]", record_ids)
        if any(not isinstance(item, str) or not _is_record_id(item) for item in entries):
            return self._respond(HTTPStatus.BAD_REQUEST, b'{"error":"invalid-record-id"}')
        if not confirm:
            payload = json.dumps(
                {
                    "requires_confirmation": True,
                    "scope_kind": "record-ids",
                    "record_ids": cast("list[str]", record_ids),
                }
            ).encode()
            return self._respond(HTTPStatus.BAD_REQUEST, payload)
        scoped = cast("list[str]", record_ids)
        return self._command(CliCommand.DELETE_RECORDS, record_ids=tuple(scoped))

    def _command(
        self,
        command: CliCommand,
        *,
        query: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        record_ids: tuple[str, ...] = (),
        target: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        result = execute_command(
            client=self._client,
            command=command,
            now=self._now(),
            timeout=timedelta(seconds=_REQUEST_TIMEOUT),
            query=query,
            start=start,
            end=end,
            record_ids=record_ids,
            target=target,
        )
        return self._render(command, result.response)

    def _render(
        self, command: CliCommand, response: CliResponse
    ) -> tuple[int, dict[str, str], bytes]:
        if response.outcome is not CliOutcome.SUCCESS:
            status = HTTPStatus.SERVICE_UNAVAILABLE
            if response.outcome is CliOutcome.INVALID:
                status = HTTPStatus.BAD_REQUEST
            elif response.outcome is CliOutcome.UNAUTHORIZED:
                status = HTTPStatus.FORBIDDEN
            payload = {"error": response.reason_code or "request-failed"}
            return self._respond(status, json.dumps(payload).encode())
        document: dict[str, object] = {
            "state": response.lifecycle_state.value if response.lifecycle_state else None
        }
        if response.query_payload is not None:
            document["kind"] = command.value
            document["result"] = json.loads(response.query_payload.to_json())
        if response.deletion_payload is not None:
            document["deleted_count"] = response.deletion_payload.deleted_count
            document["scope_kind"] = response.deletion_payload.scope_kind
        if response.status_payload is not None:
            document["privacy_mode"] = response.status_payload.privacy_mode
            document["capture_backend"] = response.status_payload.capture_backend
        return self._respond(HTTPStatus.OK, json.dumps(document).encode())

    def _respond(
        self, status: HTTPStatus, body: bytes, *, content_type: str = "application/json"
    ) -> tuple[int, dict[str, str], bytes]:
        headers: dict[str, str] = {
            "Content-Type": content_type,
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
        return int(status), headers, body


def _build_server(owner: TimelineUiServer, port: int) -> http.server.ThreadingHTTPServer:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            request_headers: dict[str, str] = {
                str(key).lower(): str(value) for key, value in self.headers.items()
            }
            context = UiRequestContext(
                method=method,
                path=parsed.path,
                query=parse_qs(parsed.query),
                headers=request_headers,
                body=body,
            )
            status, headers, payload = owner.handle(context)
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    return http.server.ThreadingHTTPServer((owner.host, port), _Handler)


def _bearer(headers: dict[str, str]) -> str | None:
    value = headers.get("authorization")
    if value is None or not value.startswith("Bearer "):
        return None
    return value.removeprefix("Bearer ").strip() or None


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _is_record_id(value: str) -> bool:
    if len(value) != 36 or value.count("-") != 4:
        return False
    allowed = set("0123456789abcdef-")
    return set(value) <= allowed
