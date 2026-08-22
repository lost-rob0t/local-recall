from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from local_recall.capture import xorg as xorg_capture
from local_recall.capture.native import BoundedNativeCommandExecutor


class FakeProcess:
    def __init__(self, *, stdout: bytes = b"", stderr: bytes = b"", block: bool = False) -> None:
        self._stdout_payload = stdout
        self._stderr_payload = stderr
        self._block = block
        self.stdout: asyncio.StreamReader | None = None
        self.stderr: asyncio.StreamReader | None = None
        self.killed = False
        self._finished: asyncio.Event | None = None
        self.returncode: int | None = None if block else 0

    def bind_to_running_loop(self) -> None:
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(self._stdout_payload)
        self.stderr.feed_data(self._stderr_payload)
        self._finished = asyncio.Event()
        if not self._block:
            self.stdout.feed_eof()
            self.stderr.feed_eof()
            self._finished.set()

    async def wait(self) -> int:
        if self._finished is None:
            raise RuntimeError("fake process was not spawned")
        await self._finished.wait()
        if self.returncode is None:
            self.returncode = -9
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        if self.stdout is not None:
            self.stdout.feed_eof()
        if self.stderr is not None:
            self.stderr.feed_eof()
        if self._finished is not None:
            self._finished.set()


class FakeSpawner:
    def __init__(self, process: FakeProcess) -> None:
        self.process = process
        self.calls: list[tuple[Path, tuple[str, ...], dict[str, str]]] = []

    async def __call__(
        self, executable: Path, args: tuple[str, ...], environment: Mapping[str, str]
    ) -> asyncio.subprocess.Process:
        self.calls.append((executable, args, dict(environment)))
        self.process.bind_to_running_loop()
        return cast(asyncio.subprocess.Process, self.process)


def _executor(
    process: FakeProcess,
    *,
    monotonic_ns: int = 1_000_000_000,
) -> tuple[BoundedNativeCommandExecutor, FakeSpawner]:
    spawner = FakeSpawner(process)
    executor = BoundedNativeCommandExecutor(
        executables={
            "xwd": Path("/usr/bin/xwd"),
            "xrandr": Path("/usr/bin/xrandr"),
        },
        environment={
            "DISPLAY": ":9",
            "XAUTHORITY": "/run/user/1000/Xauthority",
            "LD_PRELOAD": "/tmp/hostile.so",
            "HTTP_PROXY": "http://secret.invalid",
        },
        monotonic_ns=lambda: monotonic_ns,
        spawn=spawner,
    )
    return executor, spawner


def test_bounded_executor_uses_absolute_allowlist_and_minimal_environment() -> None:
    process = FakeProcess(stdout=b"capture-bytes", stderr=b"private-stderr")
    executor, spawner = _executor(process)

    result = asyncio.run(
        executor.run(
            "xwd",
            ("-root", "-silent"),
            deadline_monotonic_ns=2_000_000_000,
            max_output_bytes=64,
        )
    )

    assert result.return_code == 0
    assert result.stdout == b"capture-bytes"
    assert result.stderr == b"private-stderr"
    assert spawner.calls == [
        (
            Path("/usr/bin/xwd"),
            ("-root", "-silent"),
            {
                "DISPLAY": ":9",
                "XAUTHORITY": "/run/user/1000/Xauthority",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    ]


def test_bounded_executor_rejects_unknown_command_and_expired_deadline_before_spawn() -> None:
    process = FakeProcess()
    executor, spawner = _executor(process)

    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-command-denied"):
        asyncio.run(
            executor.run(
                "sh",
                ("-c", "id"),
                deadline_monotonic_ns=2_000_000_000,
                max_output_bytes=64,
            )
        )

    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-deadline-expired"):
        asyncio.run(
            executor.run(
                "xwd",
                ("-root",),
                deadline_monotonic_ns=1_000_000_000,
                max_output_bytes=64,
            )
        )

    assert spawner.calls == []


def test_bounded_executor_kills_live_process_on_output_limit() -> None:
    process = FakeProcess(stdout=b"123456", block=True)
    executor, _ = _executor(process)

    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-output-too-large"):
        asyncio.run(
            executor.run(
                "xwd",
                ("-root",),
                deadline_monotonic_ns=2_000_000_000,
                max_output_bytes=5,
            )
        )

    assert process.killed


def test_bounded_executor_kills_process_on_deadline() -> None:
    process = FakeProcess(block=True)
    executor, _ = _executor(process, monotonic_ns=1_000_000_000)

    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-deadline-expired"):
        asyncio.run(
            executor.run(
                "xwd",
                ("-root",),
                deadline_monotonic_ns=1_001_000_000,
                max_output_bytes=64,
            )
        )

    assert process.killed


def test_bounded_executor_kills_process_when_caller_cancels() -> None:
    process = FakeProcess(block=True)
    executor, _ = _executor(process)

    async def scenario() -> None:
        task = asyncio.create_task(
            executor.run(
                "xwd",
                ("-root",),
                deadline_monotonic_ns=10_000_000_000,
                max_output_bytes=64,
            )
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert process.killed
