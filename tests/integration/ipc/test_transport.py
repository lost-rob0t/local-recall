from __future__ import annotations

import os
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from local_recall.cli_contract import (
    CliCommand,
    CliLifecycleState,
    CliQueryPayload,
    CliRequest,
    CliResponse,
    CliStatusPayload,
)
from local_recall.ipc import IpcPaths
from local_recall.ipc_transport import ZmqDaemonClient, ZmqIpcServer


def _paths(tmp_path: Path) -> IpcPaths:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    runtime_dir.chmod(0o700)
    return IpcPaths.from_runtime_dir(runtime_dir, expected_uid=os.getuid())


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

    server = ZmqIpcServer(paths=paths, expected_uid=os.getuid(), handler=handler)
    server.start()
    try:
        client = ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        response = client.request(_request(CliCommand.STATUS))

        assert response.lifecycle_state is CliLifecycleState.PAUSED
        assert response.status_payload == CliStatusPayload(privacy_mode=False)
        socket_metadata = paths.socket_path.lstat()
        assert stat.S_ISSOCK(socket_metadata.st_mode)
        assert socket_metadata.st_uid == os.getuid()
        assert stat.S_IMODE(socket_metadata.st_mode) == 0o600
    finally:
        server.close()


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

    server = ZmqIpcServer(paths=paths, expected_uid=os.getuid(), handler=handler)
    server.start()
    query_response: list[CliResponse] = []
    try:
        query_client = ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
        query_thread = threading.Thread(
            target=lambda: query_response.append(
                query_client.request(_request(CliCommand.SEARCH, query="synthetic"))
            )
        )
        query_thread.start()
        assert query_started.wait(timeout=1)

        control_client = ZmqDaemonClient(paths=paths, expected_uid=os.getuid())
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
