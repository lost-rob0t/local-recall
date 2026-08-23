from __future__ import annotations

import os
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import zmq

from local_recall import ipc, ipc_transport
from local_recall.audit import AuditEvent, AuditRecorder
from local_recall.audit.adapters import IpcAuditAdapter
from local_recall.cli_contract import (
    CliCommand,
    CliLifecycleState,
    CliOutcome,
    CliQueryPayload,
    CliRequest,
    CliResponse,
    CliStatusPayload,
)
from local_recall.ipc_protocol import MAX_REQUEST_PAYLOAD_BYTES


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _paths(tmp_path: Path) -> ipc.IpcPaths:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    runtime_dir.chmod(0o700)
    return ipc.IpcPaths.from_runtime_dir(runtime_dir, expected_uid=os.getuid())


def _request(command: CliCommand, *, query: str | None = None) -> CliRequest:
    now = datetime.now(UTC)
    return CliRequest.create(
        command=command,
        now=now,
        deadline=now + timedelta(seconds=3),
        query=query,
    )


def test_authenticated_owner_only_ipc_round_trip(tmp_path: Path) -> None:
    paths = _paths(tmp_path)

    def handler(request: CliRequest) -> CliResponse:
        return CliResponse.success(
            request_id=request.request_id,
            lifecycle_state=CliLifecycleState.PAUSED,
            status_payload=CliStatusPayload(privacy_mode=False),
        )

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
    )
    server.start()
    try:
        client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        response = client.request(_request(CliCommand.STATUS))

        assert response.lifecycle_state is CliLifecycleState.PAUSED
        assert response.status_payload == CliStatusPayload(privacy_mode=False)
        socket_metadata = paths.socket_path.lstat()
        assert stat.S_ISSOCK(socket_metadata.st_mode)
        assert socket_metadata.st_uid == os.getuid()
        assert stat.S_IMODE(socket_metadata.st_mode) == 0o600
    finally:
        server.close()


def test_router_enforces_native_inbound_message_limit(tmp_path: Path) -> None:
    paths = _paths(tmp_path)

    def handler(request: CliRequest) -> CliResponse:
        return CliResponse.success(
            request_id=request.request_id,
            lifecycle_state=CliLifecycleState.PAUSED,
        )

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
    )
    server.start()
    try:
        socket = server._socket
        assert socket is not None
        assert socket.getsockopt(zmq.MAXMSGSIZE) == MAX_REQUEST_PAYLOAD_BYTES
    finally:
        server.close()


def test_authorized_request_emits_content_free_ipc_audit_event(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    sink = MemoryAuditSink()
    audit = IpcAuditAdapter(AuditRecorder(sink))
    private_marker = "SYNTHETIC-PRIVATE-QUERY-MARKER"

    def handler(request: CliRequest) -> CliResponse:
        return CliResponse.success(
            request_id=request.request_id,
            query_payload=CliQueryPayload(text="synthetic result"),
        )

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
        audit=audit,
    )
    server.start()
    try:
        client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        response = client.request(_request(CliCommand.SEARCH, query=private_marker))
    finally:
        server.close()

    assert response.query_payload == CliQueryPayload(text="synthetic result")
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.attributes == {
        "authorized": True,
        "control": False,
        "diagnostic": False,
        "query": True,
        "urgent": False,
    }
    assert private_marker not in repr(event)


def test_failed_authentication_is_audited_without_dispatch(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    sink = MemoryAuditSink()
    audit = IpcAuditAdapter(AuditRecorder(sink))
    handler_called = threading.Event()

    def handler(request: CliRequest) -> CliResponse:
        handler_called.set()
        return CliResponse.success(
            request_id=request.request_id,
            lifecycle_state=CliLifecycleState.PAUSED,
        )

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
        audit=audit,
    )
    server.start()
    try:
        ipc.IpcCredentialStore(paths, os.getuid()).initialize()
        client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        response = client.request(_request(CliCommand.STATUS))
    finally:
        server.close()

    assert response.outcome is CliOutcome.INVALID
    assert response.reason_code == "ipc-rejected"
    assert not handler_called.is_set()
    assert len(sink.events) == 1
    assert sink.events[0].attributes == {
        "authorized": False,
        "control": False,
        "diagnostic": False,
        "query": False,
        "urgent": False,
    }


def test_stop_is_not_starved_by_blocked_query(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    query_started = threading.Event()
    release_query = threading.Event()

    def handler(request: CliRequest) -> CliResponse:
        if request.command is CliCommand.SEARCH:
            query_started.set()
            if not release_query.wait(timeout=2):
                raise RuntimeError("synthetic query was never released")
            return CliResponse.success(
                request_id=request.request_id,
                query_payload=CliQueryPayload(text="synthetic result"),
            )
        return CliResponse.success(
            request_id=request.request_id,
            lifecycle_state=CliLifecycleState.OFF,
        )

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
    )
    server.start()
    query_response: list[CliResponse] = []
    try:
        query_client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        query_thread = threading.Thread(
            target=lambda: query_response.append(
                query_client.request(_request(CliCommand.SEARCH, query="synthetic"))
            )
        )
        query_thread.start()
        assert query_started.wait(timeout=1)

        control_client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        stop_response = control_client.request(_request(CliCommand.STOP))

        assert stop_response.lifecycle_state is CliLifecycleState.OFF
        assert query_thread.is_alive()
        release_query.set()
        query_thread.join(timeout=2)
        assert not query_thread.is_alive()
        assert query_response[0].query_payload == CliQueryPayload(text="synthetic result")
    finally:
        release_query.set()
        server.close()


def test_stop_has_reserved_capacity_when_query_lane_is_saturated(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    all_queries_started = threading.Event()
    release_queries = threading.Event()
    started_count = 0
    started_lock = threading.Lock()

    def handler(request: CliRequest) -> CliResponse:
        nonlocal started_count
        if request.command is CliCommand.SEARCH:
            with started_lock:
                started_count += 1
                if started_count == 4:
                    all_queries_started.set()
            if not release_queries.wait(timeout=2):
                raise RuntimeError("synthetic saturated queries were never released")
            return CliResponse.success(
                request_id=request.request_id,
                query_payload=CliQueryPayload(text="synthetic result"),
            )
        return CliResponse.success(
            request_id=request.request_id,
            lifecycle_state=CliLifecycleState.OFF,
        )

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
        max_pending=4,
    )
    server.start()
    query_threads: list[threading.Thread] = []
    query_responses: list[CliResponse] = []

    def run_query(index: int) -> None:
        client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        query_responses.append(
            client.request(_request(CliCommand.SEARCH, query=f"synthetic-{index}"))
        )

    try:
        for index in range(4):
            thread = threading.Thread(target=run_query, args=(index,))
            query_threads.append(thread)
            thread.start()
        assert all_queries_started.wait(timeout=1)

        control_client = ipc_transport.ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        stop_response = control_client.request(_request(CliCommand.STOP))

        assert stop_response.lifecycle_state is CliLifecycleState.OFF
        assert all(thread.is_alive() for thread in query_threads)
    finally:
        release_queries.set()
        for thread in query_threads:
            thread.join(timeout=2)
        server.close()

    assert len(query_responses) == 4
