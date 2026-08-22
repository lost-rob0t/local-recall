"""Bounded process isolation for native desktop capture helpers."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from time import monotonic_ns as system_monotonic_ns
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from local_recall.capture.xorg import NativeCommandResult

_ALLOWED_COMMANDS = frozenset({"xwd", "xrandr"})
_MAX_STDERR_BYTES = 16 * 1024

SpawnProcess = Callable[
    [Path, tuple[str, ...], Mapping[str, str]], Awaitable[asyncio.subprocess.Process]
]


class _OutputLimitExceeded(RuntimeError):
    pass


class BoundedNativeCommandExecutor:
    """Run fixed absolute native helpers with bounded memory and lifetime."""

    def __init__(
        self,
        *,
        executables: Mapping[str, Path],
        environment: Mapping[str, str],
        monotonic_ns: Callable[[], int] = system_monotonic_ns,
        spawn: SpawnProcess | None = None,
    ) -> None:
        if not executables or not set(executables).issubset(_ALLOWED_COMMANDS):
            raise ValueError("native executable allowlist is invalid")
        normalized: dict[str, Path] = {}
        for command, executable in executables.items():
            if not executable.is_absolute():
                raise ValueError("native executable path must be absolute")
            normalized[command] = executable
        self._executables = normalized
        self._environment = _minimal_environment(environment)
        self._monotonic_ns = monotonic_ns
        self._spawn = spawn or _spawn_process

    async def run(
        self,
        command: str,
        args: tuple[str, ...],
        *,
        deadline_monotonic_ns: int,
        max_output_bytes: int,
    ) -> NativeCommandResult:
        from local_recall.capture.xorg import NativeCommandResult, XorgCaptureError

        executable = self._executables.get(command)
        if executable is None:
            raise XorgCaptureError("capture-command-denied")
        if max_output_bytes <= 0:
            raise XorgCaptureError("capture-output-too-large")
        remaining_ns = deadline_monotonic_ns - self._monotonic_ns()
        if remaining_ns <= 0:
            raise XorgCaptureError("capture-deadline-expired")

        try:
            process = await self._spawn(executable, args, self._environment)
        except OSError:
            raise XorgCaptureError("capture-executable-unavailable") from None
        if process.stdout is None or process.stderr is None:
            await _kill_process(process, ())
            raise XorgCaptureError("capture-execution-failed")

        stdout_task = asyncio.create_task(_read_bounded(process.stdout, max_output_bytes))
        stderr_task = asyncio.create_task(
            _read_bounded(process.stderr, min(max_output_bytes, _MAX_STDERR_BYTES))
        )
        wait_task = asyncio.create_task(process.wait())
        tasks = (stdout_task, stderr_task, wait_task)
        try:
            stdout, stderr, return_code = await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=remaining_ns / 1_000_000_000
            )
        except asyncio.CancelledError:
            await _kill_process(process, tasks)
            raise
        except TimeoutError:
            await _kill_process(process, tasks)
            raise XorgCaptureError("capture-deadline-expired") from None
        except _OutputLimitExceeded:
            await _kill_process(process, tasks)
            raise XorgCaptureError("capture-output-too-large") from None
        except Exception:
            await _kill_process(process, tasks)
            raise XorgCaptureError("capture-execution-failed") from None
        return NativeCommandResult(return_code=return_code, stdout=stdout, stderr=stderr)


async def _spawn_process(
    executable: Path, args: tuple[str, ...], environment: Mapping[str, str]
) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        os.fspath(executable),
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=dict(environment),
    )


def _minimal_environment(environment: Mapping[str, str]) -> dict[str, str]:
    result = {"LANG": "C", "LC_ALL": "C"}
    display = environment.get("DISPLAY")
    if display:
        result["DISPLAY"] = display
    xauthority = environment.get("XAUTHORITY")
    if xauthority:
        result["XAUTHORITY"] = xauthority
    elif home := environment.get("HOME"):
        result["HOME"] = home
    return result


async def _read_bounded(stream: asyncio.StreamReader, limit: int) -> bytes:
    payload = bytearray()
    while True:
        remaining = limit - len(payload)
        chunk = await stream.read(min(4096, remaining + 1))
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > limit:
            raise _OutputLimitExceeded


async def _kill_process(
    process: asyncio.subprocess.Process,
    tasks: tuple[asyncio.Task[bytes], asyncio.Task[bytes], asyncio.Task[int]] | tuple[()],
) -> None:
    if process.returncode is None:
        process.kill()
    await process.wait()
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
