from __future__ import annotations

import os
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from local_recall import ipc, ipc_transport
from local_recall.cli_contract import (
    CliCommand,
    CliLifecycleState,
    CliOutcome,
    CliRequest,
    CliResponse,
)


def test_handler_success_after_deadline_is_rejected(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    runtime_dir.chmod(0o700)
    paths = ipc.IpcPaths.from_runtime_dir(runtime_dir, expected_uid=os.getuid())
    now = datetime.now(UTC)
    request = CliRequest.create(
        command=CliCommand.STATUS,
        now=now,
        deadline=now + timedelta(milliseconds=10),
    )

    def handler(current: CliRequest) -> CliResponse:
        time.sleep(0.03)
        return CliResponse.success(
            request_id=current.request_id,
            lifecycle_state=CliLifecycleState.PAUSED,
        )

    server = ipc_transport.ZmqIpcServer(
        paths=paths,
        expected_uid=os.getuid(),
        handler=handler,
    )
    invoke = cast(
        Callable[[CliRequest], CliResponse],
        getattr(server, "_invoke_handler"),
    )

    response = invoke(request)

    assert response.outcome is CliOutcome.TIMEOUT
    assert response.reason_code == "deadline-expired"
