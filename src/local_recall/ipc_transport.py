"""Authenticated owner-only ZeroMQ IPC transport for Local Recall."""

from __future__ import annotations

import contextlib
import json
import os
import stat
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import zmq

from local_recall.audit.adapters import IpcAuditAdapter
from local_recall.audit.errors import AuditFailure
from local_recall.cli_contract import (
    PROTOCOL_VERSION,
    CliCitation,
    CliCommand,
    CliDiagnosticCategory,
    CliDiagnosticEntry,
    CliDiagnosticPayload,
    CliLifecycleState,
    CliOutcome,
    CliPriority,
    CliQueryPayload,
    CliRequest,
    CliResponse,
    CliStatusPayload,
)
from local_recall.ipc import IpcCredentialStore, IpcPaths, IpcSecurityError
from local_recall.ipc_protocol import (
    IpcCapability,
    IpcProtocolError,
    IpcRequestCodec,
)

_MAX_RESPONSE_BYTES = 1_310_720
_MAX_PENDING = 32
_MAX_URGENT_PENDING = 4
_POLL_MS = 25


class IpcTransportError(RuntimeError):
    """Fixed, content-free local transport failure."""


RequestHandler = Callable[[CliRequest], CliResponse]


@dataclass(slots=True)
class _PendingReply:
    identity: bytes
    request_id: str
    future: Future[CliResponse]
    urgent: bool


@dataclass(slots=True, repr=False)
class ZmqIpcServer:
    """Owner-only ROUTER endpoint with bounded concurrent request dispatch."""

    paths: IpcPaths
    expected_uid: int
    handler: RequestHandler
    audit: IpcAuditAdapter | None = None
    max_pending: int = _MAX_PENDING
    _context: zmq.Context[zmq.Socket[bytes]] | None = field(default=None, init=False, repr=False)
    _socket: zmq.Socket[bytes] | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _executor: ThreadPoolExecutor | None = field(default=None, init=False, repr=False)
    _urgent_executor: ThreadPoolExecutor | None = field(default=None, init=False, repr=False)
    _codec: IpcRequestCodec | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        """Create credentials, bind the private socket, and start serving."""
        if self._thread is not None:
            raise IpcTransportError("already-started")
        if self.max_pending < 2 or self.max_pending > 256:
            raise IpcTransportError("invalid-concurrency")

        store = IpcCredentialStore(self.paths, self.expected_uid)
        token = store.initialize()
        self._remove_stale_socket()

        context: zmq.Context[zmq.Socket[bytes]] = zmq.Context()
        socket = context.socket(zmq.ROUTER)
        socket.setsockopt(zmq.LINGER, 0)
        socket.setsockopt(zmq.SNDHWM, self.max_pending + _MAX_URGENT_PENDING)
        socket.setsockopt(zmq.RCVHWM, self.max_pending + _MAX_URGENT_PENDING)
        if hasattr(zmq, "IPC_FILTER_UID"):
            socket.setsockopt(zmq.IPC_FILTER_UID, self.expected_uid)
        try:
            socket.bind(self._endpoint())
            os.chmod(self.paths.socket_path, 0o600, follow_symlinks=False)
            self._validate_bound_socket()
        except OSError, zmq.ZMQError, IpcSecurityError:
            socket.close(linger=0)
            context.term()
            raise IpcTransportError("bind-failed") from None

        self._context = context
        self._socket = socket
        self._codec = IpcRequestCodec(
            token=token,
            capabilities=frozenset(
                {
                    IpcCapability.CONTROL,
                    IpcCapability.QUERY,
                    IpcCapability.DIAGNOSTIC,
                }
            ),
        )
        self._executor = ThreadPoolExecutor(max_workers=min(self.max_pending, 8))
        self._urgent_executor = ThreadPoolExecutor(max_workers=2)
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="local-recall-ipc", daemon=True)
        self._thread.start()

    def close(self) -> None:
        """Stop serving and remove only the validated daemon-owned socket node."""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        executor = self._executor
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        urgent_executor = self._urgent_executor
        if urgent_executor is not None:
            urgent_executor.shutdown(wait=False, cancel_futures=True)
        socket = self._socket
        if socket is not None:
            socket.close(linger=0)
        context = self._context
        if context is not None:
            context.term()
        self._cleanup_socket()
        self._thread = None
        self._executor = None
        self._urgent_executor = None
        self._socket = None
        self._context = None
        self._codec = None

    def _serve(self) -> None:
        socket = self._require_socket()
        codec = self._require_codec()
        executor = self._require_executor()
        urgent_executor = self._require_urgent_executor()
        pending: list[_PendingReply] = []
        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        while not self._stop.is_set():
            self._flush_completed(socket, pending)
            try:
                events = dict(poller.poll(_POLL_MS))
            except zmq.ZMQError:
                break
            if socket not in events:
                continue
            try:
                frames = socket.recv_multipart(flags=zmq.NOBLOCK)
            except zmq.Again:
                continue
            except zmq.ZMQError:
                break
            if len(frames) != 4:
                continue
            identity, *request_frames = frames
            try:
                request = codec.decode(tuple(request_frames), now=datetime.now(UTC))
            except IpcProtocolError:
                request_id = _request_id_hint(request_frames)
                if self.audit is not None:
                    try:
                        self.audit.rejected(
                            capability=None,
                            urgent=False,
                            correlation_id=_correlation_id_hint(request_frames),
                        )
                    except AuditFailure, ValueError:
                        self._send_failure(
                            socket,
                            identity,
                            request_id,
                            "audit-failed",
                            outcome=CliOutcome.INTERNAL_FAILURE,
                        )
                        continue
                self._send_failure(socket, identity, request_id, "ipc-rejected")
                continue

            urgent = request.priority is CliPriority.URGENT_CONTROL
            if self.audit is not None:
                try:
                    self.audit.accepted(
                        capability=_audit_capability(request.command),
                        urgent=urgent,
                        correlation_id=UUID(hex=request.request_id),
                    )
                except AuditFailure, ValueError:
                    self._send_failure(
                        socket,
                        identity,
                        request.request_id,
                        "audit-failed",
                        outcome=CliOutcome.INTERNAL_FAILURE,
                    )
                    continue

            lane_pending = sum(item.urgent is urgent for item in pending)
            lane_limit = _MAX_URGENT_PENDING if urgent else self.max_pending
            if lane_pending >= lane_limit:
                self._send_failure(
                    socket,
                    identity,
                    request.request_id,
                    "ipc-overloaded",
                    outcome=CliOutcome.OVERLOADED,
                )
                continue

            lane_executor = urgent_executor if urgent else executor
            future = lane_executor.submit(self._invoke_handler, request)
            pending.append(
                _PendingReply(
                    identity=identity,
                    request_id=request.request_id,
                    future=future,
                    urgent=urgent,
                )
            )

        deadline = time.monotonic() + 0.25
        while pending and time.monotonic() < deadline:
            self._flush_completed(socket, pending)
            time.sleep(0.005)

    def _invoke_handler(self, request: CliRequest) -> CliResponse:
        try:
            response = self.handler(request)
        except Exception:
            return CliResponse.failure(
                request_id=request.request_id,
                outcome=CliOutcome.INTERNAL_FAILURE,
                reason_code="handler-failed",
            )
        if response.request_id != request.request_id:
            return CliResponse.failure(
                request_id=request.request_id,
                outcome=CliOutcome.INTERNAL_FAILURE,
                reason_code="response-id-mismatch",
            )
        return response

    @staticmethod
    def _flush_completed(socket: zmq.Socket[bytes], pending: list[_PendingReply]) -> None:
        remaining: list[_PendingReply] = []
        for item in pending:
            if not item.future.done():
                remaining.append(item)
                continue
            try:
                response = item.future.result()
            except Exception:
                response = CliResponse.failure(
                    request_id=item.request_id,
                    outcome=CliOutcome.INTERNAL_FAILURE,
                    reason_code="handler-failed",
                )
            payload = response.to_json().encode("utf-8")
            if len(payload) > _MAX_RESPONSE_BYTES:
                payload = (
                    CliResponse.failure(
                        request_id=item.request_id,
                        outcome=CliOutcome.INTERNAL_FAILURE,
                        reason_code="response-too-large",
                    )
                    .to_json()
                    .encode("utf-8")
                )
            with contextlib.suppress(zmq.Again, zmq.ZMQError):
                _send_frames(socket, (item.identity, payload), flags=zmq.NOBLOCK)
        pending[:] = remaining

    @staticmethod
    def _send_failure(
        socket: zmq.Socket[bytes],
        identity: bytes,
        request_id: str,
        reason_code: str,
        *,
        outcome: CliOutcome = CliOutcome.INVALID,
    ) -> None:
        response = CliResponse.failure(
            request_id=request_id,
            outcome=outcome,
            reason_code=reason_code,
        )
        with contextlib.suppress(zmq.Again, zmq.ZMQError):
            _send_frames(
                socket,
                (identity, response.to_json().encode("utf-8")),
                flags=zmq.NOBLOCK,
            )

    def _endpoint(self) -> str:
        return f"ipc://{self.paths.socket_path}"

    def _remove_stale_socket(self) -> None:
        try:
            metadata = self.paths.socket_path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise IpcTransportError("socket-unavailable") from None
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != self.expected_uid:
            raise IpcTransportError("unsafe-stale-socket")
        try:
            self.paths.socket_path.unlink()
        except OSError:
            raise IpcTransportError("socket-remove") from None

    def _validate_bound_socket(self) -> None:
        try:
            metadata = self.paths.socket_path.lstat()
        except OSError:
            raise IpcSecurityError("socket-unavailable") from None
        if not stat.S_ISSOCK(metadata.st_mode):
            raise IpcSecurityError("socket-type")
        if metadata.st_uid != self.expected_uid:
            raise IpcSecurityError("socket-owner")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise IpcSecurityError("socket-mode")

    def _cleanup_socket(self) -> None:
        try:
            metadata = self.paths.socket_path.lstat()
        except OSError:
            return
        if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == self.expected_uid:
            with contextlib.suppress(OSError):
                self.paths.socket_path.unlink()

    def _require_socket(self) -> zmq.Socket[bytes]:
        if self._socket is None:
            raise IpcTransportError("not-started")
        return self._socket

    def _require_codec(self) -> IpcRequestCodec:
        if self._codec is None:
            raise IpcTransportError("not-started")
        return self._codec

    def _require_executor(self) -> ThreadPoolExecutor:
        if self._executor is None:
            raise IpcTransportError("not-started")
        return self._executor

    def _require_urgent_executor(self) -> ThreadPoolExecutor:
        if self._urgent_executor is None:
            raise IpcTransportError("not-started")
        return self._urgent_executor

    def __repr__(self) -> str:
        return "ZmqIpcServer(paths=<private>, expected_uid=<uid>)"


@dataclass(frozen=True, slots=True, repr=False)
class ZmqDaemonClient:
    """Authenticated DEALER client implementing the daemon request boundary."""

    paths: IpcPaths
    expected_uid: int

    def request(self, request: CliRequest) -> CliResponse:
        store = IpcCredentialStore(self.paths, self.expected_uid)
        try:
            token = store.load()
        except IpcSecurityError, OSError:
            return CliResponse.failure(
                request_id=request.request_id,
                outcome=CliOutcome.UNAVAILABLE,
                reason_code="daemon-unavailable",
            )
        codec = IpcRequestCodec(
            token=token,
            capabilities=frozenset(
                {
                    IpcCapability.CONTROL,
                    IpcCapability.QUERY,
                    IpcCapability.DIAGNOSTIC,
                }
            ),
        )
        frames = codec.encode(request)
        remaining = (request.deadline - datetime.now(UTC)).total_seconds()
        if remaining <= 0:
            return CliResponse.failure(
                request_id=request.request_id,
                outcome=CliOutcome.TIMEOUT,
                reason_code="deadline-expired",
            )
        timeout_ms = max(1, min(int(remaining * 1000), 30_000))

        context: zmq.Context[zmq.Socket[bytes]] = zmq.Context()
        socket = context.socket(zmq.DEALER)
        socket.setsockopt(zmq.LINGER, 0)
        socket.setsockopt(zmq.SNDHWM, 8)
        socket.setsockopt(zmq.RCVHWM, 8)
        socket.setsockopt(zmq.SNDTIMEO, timeout_ms)
        socket.setsockopt(zmq.RCVTIMEO, timeout_ms)
        try:
            socket.connect(f"ipc://{self.paths.socket_path}")
            _send_frames(socket, frames)
            response_frames = socket.recv_multipart()
        except zmq.Again:
            return CliResponse.failure(
                request_id=request.request_id,
                outcome=CliOutcome.TIMEOUT,
                reason_code="ipc-timeout",
            )
        except zmq.ZMQError:
            return CliResponse.failure(
                request_id=request.request_id,
                outcome=CliOutcome.UNAVAILABLE,
                reason_code="daemon-unavailable",
            )
        finally:
            socket.close(linger=0)
            context.term()

        if len(response_frames) != 1 or len(response_frames[0]) > _MAX_RESPONSE_BYTES:
            raise IpcTransportError("invalid-response")
        response = _decode_response(response_frames[0])
        if response.request_id != request.request_id:
            raise IpcTransportError("response-id-mismatch")
        return response

    def __repr__(self) -> str:
        return "ZmqDaemonClient(paths=<private>, expected_uid=<uid>)"


def daemon_client_from_environment() -> ZmqDaemonClient:
    """Construct the authenticated local client from the private XDG runtime directory."""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime is None or not runtime:
        raise IpcTransportError("runtime-unavailable")
    expected_uid = os.getuid()
    try:
        paths = IpcPaths.from_runtime_dir(Path(runtime), expected_uid=expected_uid)
    except IpcSecurityError, OSError, ValueError:
        raise IpcTransportError("runtime-unavailable") from None
    return ZmqDaemonClient(paths=paths, expected_uid=expected_uid)


def _audit_capability(command: CliCommand) -> str:
    if command in {
        CliCommand.START,
        CliCommand.PAUSE,
        CliCommand.RESUME,
        CliCommand.STOP,
        CliCommand.STATUS,
        CliCommand.PRIVACY_ON,
        CliCommand.PRIVACY_OFF,
    }:
        return "control"
    if command in {CliCommand.ASK, CliCommand.TIMELINE, CliCommand.SEARCH}:
        return "query"
    if command in {CliCommand.PROVIDERS, CliCommand.HEALTH, CliCommand.STORAGE_STATS}:
        return "diagnostic"
    raise ValueError("unsupported IPC capability")


def _send_frames(socket: zmq.Socket[bytes], frames: tuple[bytes, ...], *, flags: int = 0) -> None:
    if not frames:
        raise IpcTransportError("empty-message")
    last_index = len(frames) - 1
    for index, frame in enumerate(frames):
        send_flags = flags | (zmq.SNDMORE if index != last_index else 0)
        socket.send(frame, flags=send_flags)


def _request_id_hint(frames: list[bytes]) -> str:
    if not frames:
        return "0" * 32
    try:
        loaded = cast(object, json.loads(frames[0].decode("utf-8", errors="strict")))
    except UnicodeDecodeError, json.JSONDecodeError:
        return "0" * 32
    if not isinstance(loaded, dict):
        return "0" * 32
    value = cast(dict[object, object], loaded).get("request_id")
    if not isinstance(value, str) or len(value) != 32:
        return "0" * 32
    if any(character not in "0123456789abcdef" for character in value):
        return "0" * 32
    return value


def _correlation_id_hint(frames: list[bytes]) -> UUID | None:
    value = _request_id_hint(frames)
    try:
        correlation_id = UUID(hex=value)
    except ValueError:
        return None
    if correlation_id.version != 4:
        return None
    return correlation_id


def _decode_response(frame: bytes) -> CliResponse:
    try:
        loaded = cast(object, json.loads(frame.decode("utf-8", errors="strict")))
    except UnicodeDecodeError, json.JSONDecodeError:
        raise IpcTransportError("invalid-response") from None
    if not isinstance(loaded, dict):
        raise IpcTransportError("invalid-response")
    values = cast(dict[str, object], loaded)
    try:
        if values.get("protocol_version") != PROTOCOL_VERSION:
            raise ValueError
        request_id = _required_string(values, "request_id")
        outcome = CliOutcome(_required_string(values, "outcome"))
        reason_code = _optional_string(values, "reason_code")
        lifecycle_raw = _optional_string(values, "lifecycle_state")
        lifecycle = CliLifecycleState(lifecycle_raw) if lifecycle_raw is not None else None
        query_payload = _decode_query_payload(values.get("query_payload"))
        diagnostic_payload = _decode_diagnostic_payload(values.get("diagnostic_payload"))
        status_payload = _decode_status_payload(values.get("status_payload"))
        if outcome is CliOutcome.SUCCESS:
            return CliResponse.success(
                request_id=request_id,
                lifecycle_state=lifecycle,
                query_payload=query_payload,
                diagnostic_payload=diagnostic_payload,
                status_payload=status_payload,
            )
        if reason_code is None:
            raise ValueError
        return CliResponse.failure(request_id=request_id, outcome=outcome, reason_code=reason_code)
    except TypeError, ValueError, KeyError:
        raise IpcTransportError("invalid-response") from None


def _decode_query_payload(value: object) -> CliQueryPayload | None:
    if value is None:
        return None
    mapping = _mapping(value)
    text = _required_string(mapping, "text")
    citations_raw = mapping.get("citations")
    if not isinstance(citations_raw, list):
        raise ValueError
    citations: list[CliCitation] = []
    for item in cast(list[object], citations_raw):
        citation = _mapping(item)
        citations.append(
            CliCitation(
                record_id=_required_string(citation, "record_id"),
                captured_at=datetime.fromisoformat(_required_string(citation, "captured_at")),
            )
        )
    return CliQueryPayload(text=text, citations=tuple(citations))


def _decode_diagnostic_payload(value: object) -> CliDiagnosticPayload | None:
    if value is None:
        return None
    mapping = _mapping(value)
    category = CliDiagnosticCategory(_required_string(mapping, "category"))
    entries_raw = mapping.get("entries")
    if not isinstance(entries_raw, list):
        raise ValueError
    entries: list[CliDiagnosticEntry] = []
    for item in cast(list[object], entries_raw):
        entry = _mapping(item)
        entries.append(
            CliDiagnosticEntry(
                name=_required_string(entry, "name"),
                state=_required_string(entry, "state"),
                value=_optional_string(entry, "value"),
            )
        )
    return CliDiagnosticPayload(category=category, entries=tuple(entries))


def _decode_status_payload(value: object) -> CliStatusPayload | None:
    if value is None:
        return None
    mapping = _mapping(value)
    privacy_mode = mapping.get("privacy_mode")
    if not isinstance(privacy_mode, bool):
        raise ValueError
    last_capture_raw = _optional_string(mapping, "last_capture_at")
    return CliStatusPayload(
        privacy_mode=privacy_mode,
        capture_backend=_optional_string(mapping, "capture_backend"),
        metadata_source=_optional_string(mapping, "metadata_source"),
        last_capture_at=(
            datetime.fromisoformat(last_capture_raw) if last_capture_raw is not None else None
        ),
    )


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError
    raw = cast(dict[object, object], value)
    result: dict[str, object] = {}
    for key, item in raw.items():
        if not isinstance(key, str):
            raise ValueError
        result[key] = item
    return result


def _required_string(values: dict[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str):
        raise ValueError
    return value


def _optional_string(values: dict[str, object], key: str) -> str | None:
    value = values.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError
    return value
