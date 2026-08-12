from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from .safety import (
    LockObservation,
    LockState,
    SafetyObservationRequest,
    SessionSafetyFailureCode,
)

_SOURCE_ID = "logind"
_SOURCE_REVISION = "login1-busctl-v1"
_SERVICE = "org.freedesktop.login1"
_MANAGER_PATH = "/org/freedesktop/login1"
_MANAGER_INTERFACE = "org.freedesktop.login1.Manager"
_SESSION_INTERFACE = "org.freedesktop.login1.Session"
_SESSION_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SESSION_PATH = re.compile(r"^/org/freedesktop/login1/session/[A-Za-z0-9_]{1,128}$")
_GET_SESSION = re.compile(rb'^o "(/org/freedesktop/login1/session/[A-Za-z0-9_]{1,128})"\s*$')
_LOCKED_HINT = re.compile(rb"^b (true|false)\s*$")
_DEFAULT_TIMEOUT_SECONDS = 0.5
_MAX_OUTPUT_BYTES = 4096
_MAX_SIGNAL_LINE_BYTES = 1024
_MAX_SIGNAL_LINES = 24


@dataclass(frozen=True, slots=True, repr=False)
class BusctlResult:
    return_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(default=b"", repr=False)

    def __repr__(self) -> str:
        return (
            f"BusctlResult(return_code={self.return_code}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)})"
        )


@dataclass(frozen=True, slots=True)
class LogindSignal:
    object_path: str
    interface: str
    member: str

    def __post_init__(self) -> None:
        if not _SESSION_PATH.fullmatch(self.object_path):
            raise ValueError("invalid logind session object path")
        if self.interface != _SESSION_INTERFACE:
            raise ValueError("invalid logind signal interface")
        if self.member not in {"Lock", "Unlock"}:
            raise ValueError("invalid logind signal member")


@runtime_checkable
class BusctlRunner(Protocol):
    @property
    def available(self) -> bool: ...

    async def run(
        self,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> BusctlResult: ...


class FixedBusctlRunner:
    def __init__(
        self,
        executable: Path | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        environment = os.environ if environ is None else environ
        search_path = environment.get("PATH")
        resolved = (
            shutil.which("busctl", path=search_path) if executable is None else str(executable)
        )
        self._executable = None if resolved is None else Path(resolved).resolve()
        if self._executable is not None and self._executable.name != "busctl":
            raise ValueError("logind adapter must use the fixed busctl executable")
        self._environment = dict(environment)
        self._environment["LC_ALL"] = "C"
        self._environment["LANG"] = "C"

    @property
    def executable(self) -> Path | None:
        return self._executable

    @property
    def environment(self) -> Mapping[str, str]:
        return self._environment

    @property
    def available(self) -> bool:
        path = self._executable
        return bool(path is not None and path.is_file() and os.access(path, os.X_OK))

    async def run(
        self,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> BusctlResult:
        executable = self._executable
        if executable is None or not self.available:
            raise FileNotFoundError("busctl unavailable")
        process = await asyncio.create_subprocess_exec(
            str(executable),
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._environment,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        if len(stdout) > max_output_bytes or len(stderr) > max_output_bytes:
            raise ValueError("logind source output exceeded bound")
        return BusctlResult(process.returncode or 0, stdout, stderr)


class LogindLockStateSource:
    def __init__(
        self,
        session_id: str,
        *,
        runner: BusctlRunner | None = None,
        now: Callable[[], datetime] | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not _SESSION_ID.fullmatch(session_id):
            raise ValueError("invalid logind session identifier")
        if timeout_seconds <= 0 or timeout_seconds > 5:
            raise ValueError("logind timeout must be between 0 and 5 seconds")
        self._session_id = session_id
        self._runner = runner or FixedBusctlRunner()
        self._now = now or (lambda: datetime.now(UTC))
        self._timeout_seconds = timeout_seconds
        self._session_path: str | None = None

    @property
    def source_id(self) -> str:
        return _SOURCE_ID

    @property
    def session_path(self) -> str | None:
        return self._session_path

    async def observe(self, request: SafetyObservationRequest) -> LockObservation:
        if not self._runner.available:
            return self._unknown(SessionSafetyFailureCode.UNAVAILABLE)
        try:
            session_path = self._session_path or await self._resolve_session_path(request)
            result = await self._runner.run(
                (
                    "--system",
                    "get-property",
                    _SERVICE,
                    session_path,
                    _SESSION_INTERFACE,
                    "LockedHint",
                ),
                timeout_seconds=self._remaining_timeout(request),
                max_output_bytes=_MAX_OUTPUT_BYTES,
            )
        except TimeoutError:
            return self._unknown(SessionSafetyFailureCode.TIMEOUT)
        except PermissionError:
            return self._unknown(SessionSafetyFailureCode.PERMISSION_DENIED)
        except ValueError:
            self._session_path = None
            return self._unknown(SessionSafetyFailureCode.MALFORMED)
        except Exception:
            self._session_path = None
            return self._unknown(SessionSafetyFailureCode.UNAVAILABLE)
        if result.return_code != 0:
            self._session_path = None
            return self._unknown(SessionSafetyFailureCode.UNAVAILABLE)
        match = _LOCKED_HINT.fullmatch(result.stdout)
        if match is None:
            return self._unknown(SessionSafetyFailureCode.MALFORMED)
        return LockObservation(
            state=LockState.LOCKED if match.group(1) == b"true" else LockState.UNLOCKED,
            observed_at=self._now(),
            source_id=self.source_id,
            source_revision=_SOURCE_REVISION,
        )

    def signal_observation(
        self,
        signal: LogindSignal,
        *,
        observed_at: datetime | None = None,
    ) -> LockObservation | None:
        target = self._session_path
        if target is None or signal.object_path != target:
            return None
        if signal.member == "Unlock":
            # login1 Unlock() is a request to the session manager, not proof that
            # the lock screen has actually released. Stay fail-closed until a
            # fresh LockedHint=false query confirms current state.
            return LockObservation(
                state=LockState.UNKNOWN,
                observed_at=observed_at or self._now(),
                source_id=self.source_id,
                source_revision=_SOURCE_REVISION,
                failure_code=SessionSafetyFailureCode.STALE,
            )
        return LockObservation(
            state=LockState.LOCKED,
            observed_at=observed_at or self._now(),
            source_id=self.source_id,
            source_revision=_SOURCE_REVISION,
        )

    def disconnected(self) -> LockObservation:
        self._session_path = None
        return self._unknown(SessionSafetyFailureCode.DISCONNECTED)

    async def _resolve_session_path(self, request: SafetyObservationRequest) -> str:
        result = await self._runner.run(
            (
                "--system",
                "call",
                _SERVICE,
                _MANAGER_PATH,
                _MANAGER_INTERFACE,
                "GetSession",
                "s",
                self._session_id,
            ),
            timeout_seconds=self._remaining_timeout(request),
            max_output_bytes=_MAX_OUTPUT_BYTES,
        )
        if result.return_code != 0:
            raise RuntimeError("logind session lookup failed")
        match = _GET_SESSION.fullmatch(result.stdout)
        if match is None:
            raise ValueError("malformed logind session path")
        session_path = match.group(1).decode("ascii")
        if not _SESSION_PATH.fullmatch(session_path):
            raise ValueError("malformed logind session path")
        self._session_path = session_path
        return session_path

    def _remaining_timeout(self, request: SafetyObservationRequest) -> float:
        remaining = request.deadline_monotonic_ns - time.monotonic_ns()
        if remaining <= 0:
            raise TimeoutError
        return min(self._timeout_seconds, remaining / 1_000_000_000)

    def _unknown(self, failure: SessionSafetyFailureCode) -> LockObservation:
        return LockObservation(
            state=LockState.UNKNOWN,
            observed_at=self._now(),
            source_id=self.source_id,
            source_revision=_SOURCE_REVISION,
            failure_code=failure,
        )


class BusctlLogindSignalMonitor:
    def __init__(
        self,
        source: LogindLockStateSource,
        *,
        executable: Path | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        runner = FixedBusctlRunner(executable, environ=environ)
        self._source = source
        self._executable = runner.executable
        self._environment = runner.environment

    async def run(
        self,
        callback: Callable[[LockObservation], Awaitable[None] | None],
        stop: asyncio.Event,
    ) -> None:
        executable = self._executable
        if executable is None or not executable.is_file():
            await _maybe_await(callback(self._source.disconnected()))
            return
        process = await asyncio.create_subprocess_exec(
            str(executable),
            "--system",
            "monitor",
            _SERVICE,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=self._environment,
        )
        stdout = process.stdout
        if stdout is None:
            process.kill()
            await process.wait()
            await _maybe_await(callback(self._source.disconnected()))
            return
        message: list[str] = []
        try:
            while not stop.is_set():
                try:
                    raw = await asyncio.wait_for(stdout.readline(), 0.25)
                except TimeoutError:
                    continue
                if not raw:
                    break
                if len(raw) > _MAX_SIGNAL_LINE_BYTES:
                    message.clear()
                    continue
                line = raw.decode("utf-8", errors="replace").strip()
                if line.startswith("Type=signal") or "Type=signal" in line:
                    if message:
                        await self._emit_message(tuple(message), callback)
                    message = [line]
                    continue
                if not message:
                    continue
                if not line:
                    await self._emit_message(tuple(message), callback)
                    message.clear()
                    continue
                if len(message) < _MAX_SIGNAL_LINES:
                    message.append(line)
                else:
                    message.clear()
            if message:
                await self._emit_message(tuple(message), callback)
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 0.5)
                except TimeoutError:
                    process.kill()
                    await process.wait()
        if not stop.is_set():
            await _maybe_await(callback(self._source.disconnected()))

    async def _emit_message(
        self,
        lines: tuple[str, ...],
        callback: Callable[[LockObservation], Awaitable[None] | None],
    ) -> None:
        signal = parse_busctl_signal(lines)
        if signal is None:
            return
        observation = self._source.signal_observation(signal)
        if observation is not None:
            await _maybe_await(callback(observation))


def parse_busctl_signal(lines: tuple[str, ...]) -> LogindSignal | None:
    if len(lines) > _MAX_SIGNAL_LINES:
        return None
    path: str | None = None
    interface: str | None = None
    member: str | None = None
    for line in lines:
        if len(line.encode("utf-8")) > _MAX_SIGNAL_LINE_BYTES:
            return None
        for token in line.split():
            if token.startswith("Path="):
                path = token.removeprefix("Path=")
            elif token.startswith("Interface="):
                interface = token.removeprefix("Interface=")
            elif token.startswith("Member="):
                member = token.removeprefix("Member=")
    if path is None or interface is None or member is None:
        return None
    try:
        return LogindSignal(path, interface, member)
    except ValueError:
        return None


async def _maybe_await(value: Awaitable[None] | None) -> None:
    if value is not None:
        await value
