"""Session-bus portal gateway using bounded fixed busctl invocations."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import stat
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic_ns as system_monotonic_ns
from typing import Protocol, cast, runtime_checkable
from urllib.parse import unquote, urlparse
from uuid import uuid4

from local_recall.capture.portal import MAX_PORTAL_SCREENSHOT_BYTES, PortalError, PortalScreenshot

_PORTAL_DESTINATION = "org.freedesktop.portal.Desktop"
_PORTAL_PATH = "/org/freedesktop/portal/desktop"
_SCREENSHOT_INTERFACE = "org.freedesktop.portal.Screenshot"
_REQUEST_INTERFACE = "org.freedesktop.portal.Request"
_BUS_SCOPE = "--user"
_CALL_ARGS = (
    _BUS_SCOPE,
    "call",
    _PORTAL_DESTINATION,
    _PORTAL_PATH,
    _SCREENSHOT_INTERFACE,
    "Screenshot",
    "sa{sv}",
    "",
    "1",
    "handle_token",
    "s",
)
_REQUEST_PATH = re.compile(r'^o\s+"(/org/freedesktop/portal/desktop/request/[A-Za-z0-9_./-]+)"\s*$')
_MAX_CALL_OUTPUT_BYTES = 64 * 1024
_MAX_MONITOR_LINE_BYTES = 64 * 1024
_MAX_MONITOR_LINES = 256
_MAX_URI_LENGTH = 4096
_LOCALHOST_AUTHORITY = "localhost"


@dataclass(frozen=True, slots=True, repr=False)
class PortalCommandResult:
    return_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(default=b"", repr=False)

    def __repr__(self) -> str:
        return (
            f"PortalCommandResult(return_code={self.return_code}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)})"
        )


@runtime_checkable
class PortalCommandRunner(Protocol):
    @property
    def available(self) -> bool: ...

    async def run(
        self,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> PortalCommandResult: ...

    def read_lines(
        self,
        args: tuple[str, ...],
        *,
        deadline_monotonic_ns: int,
        max_line_bytes: int,
        max_lines: int,
    ) -> AsyncIterator[bytes]: ...


class FixedBusctlPortalRunner:
    """Run only the fixed busctl invocations required by the portal flows."""

    def __init__(
        self,
        executable: Path | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        environment = dict(os.environ if environ is None else environ)
        search_path = environment.get("PATH")
        resolved = (
            shutil.which("busctl", path=search_path) if executable is None else str(executable)
        )
        self._executable = None if resolved is None else Path(resolved).resolve()
        if self._executable is not None and self._executable.name != "busctl":
            raise ValueError("portal gateway must use the fixed busctl executable")
        environment["LC_ALL"] = "C"
        environment["LANG"] = "C"
        self._environment = environment

    @property
    def executable(self) -> Path | None:
        return self._executable

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
    ) -> PortalCommandResult:
        executable = self._executable
        if executable is None or not self.available:
            raise FileNotFoundError("busctl unavailable")
        process = await asyncio.create_subprocess_exec(
            str(executable),
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=self._environment,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(
                process.communicate(), timeout=max(timeout_seconds, 0.001)
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        if len(stdout) > max_output_bytes:
            raise ValueError("portal command output exceeded bound")
        return PortalCommandResult(process.returncode or 0, stdout, b"")

    async def read_lines(
        self,
        args: tuple[str, ...],
        *,
        deadline_monotonic_ns: int,
        max_line_bytes: int,
        max_lines: int,
    ) -> AsyncIterator[bytes]:
        executable = self._executable
        if executable is None or not self.available:
            raise FileNotFoundError("busctl unavailable")
        process = await asyncio.create_subprocess_exec(
            str(executable),
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=self._environment,
        )
        stdout = process.stdout
        if stdout is None:
            process.kill()
            await process.wait()
            raise OSError("busctl monitor stream unavailable")
        emitted = 0
        try:
            while emitted < max_lines:
                remaining = deadline_monotonic_ns - system_monotonic_ns()
                if remaining <= 0:
                    raise TimeoutError
                try:
                    raw = await asyncio.wait_for(
                        stdout.readline(), timeout=remaining / 1_000_000_000
                    )
                except TimeoutError:
                    raise
                if not raw:
                    return
                if len(raw) > max_line_bytes:
                    continue
                emitted += 1
                yield raw
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 0.5)
                except TimeoutError:
                    process.kill()
                    await process.wait()


class BusctlPortalGateway:
    """Request screenshots through the desktop portal with explicit authorization."""

    __slots__ = (
        "_max_screenshot_bytes",
        "_monotonic_ns",
        "_now",
        "_runner",
        "_token_factory",
    )

    def __init__(
        self,
        *,
        runner: PortalCommandRunner,
        token_factory: Callable[[], str] | None = None,
        now: Callable[[], datetime] | None = None,
        monotonic_ns: Callable[[], int] = system_monotonic_ns,
        max_screenshot_bytes: int = MAX_PORTAL_SCREENSHOT_BYTES,
    ) -> None:
        if max_screenshot_bytes <= 0 or max_screenshot_bytes > MAX_PORTAL_SCREENSHOT_BYTES:
            raise ValueError("portal screenshot byte bound is invalid")
        self._runner = runner
        self._token_factory = token_factory or (lambda: uuid4().hex)
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic_ns = monotonic_ns
        self._max_screenshot_bytes = max_screenshot_bytes

    async def request_screenshot(self, *, deadline_monotonic_ns: int) -> PortalScreenshot:
        if self._monotonic_ns() >= deadline_monotonic_ns:
            raise PortalError("portal-deadline-expired")
        if not self._runner.available:
            raise PortalError("portal-unavailable")
        token = self._token_factory()
        request_path = await self._call_screenshot(token, deadline_monotonic_ns)
        response_code, uri = await self._await_response(request_path, deadline_monotonic_ns)
        if response_code == 1:
            raise PortalError("portal-permission-denied")
        if response_code != 0:
            raise PortalError("portal-request-failed")
        if not isinstance(uri, str) or not uri:
            raise PortalError("portal-response-invalid")
        return self._read_screenshot(uri)

    async def _call_screenshot(self, token: str, deadline_monotonic_ns: int) -> str:
        remaining_seconds = (deadline_monotonic_ns - self._monotonic_ns()) / 1_000_000_000
        if remaining_seconds <= 0:
            raise PortalError("portal-deadline-expired")
        try:
            result = await self._runner.run(
                (*_CALL_ARGS, token),
                timeout_seconds=remaining_seconds,
                max_output_bytes=_MAX_CALL_OUTPUT_BYTES,
            )
        except TimeoutError:
            raise PortalError("portal-deadline-expired") from None
        except Exception:
            raise PortalError("portal-unavailable") from None
        if result.return_code != 0:
            raise PortalError("portal-screenshot-unavailable")
        try:
            text = result.stdout.decode("ascii")
        except UnicodeDecodeError:
            raise PortalError("portal-response-invalid") from None
        match = _REQUEST_PATH.fullmatch(text.strip())
        if match is None:
            raise PortalError("portal-response-invalid")
        return match.group(1)

    async def _await_response(
        self, request_path: str, deadline_monotonic_ns: int
    ) -> tuple[int, object]:
        match_rule = (
            f"type='signal',interface='{_REQUEST_INTERFACE}',"
            f"member='Response',path='{request_path}'"
        )
        args = (_BUS_SCOPE, "monitor", "--json=short", "--match", match_rule)
        remaining_seconds = (deadline_monotonic_ns - self._monotonic_ns()) / 1_000_000_000
        if remaining_seconds <= 0:
            raise PortalError("portal-deadline-expired")
        try:
            async with asyncio.timeout(remaining_seconds):
                async for raw in self._runner.read_lines(
                    args,
                    deadline_monotonic_ns=deadline_monotonic_ns,
                    max_line_bytes=_MAX_MONITOR_LINE_BYTES,
                    max_lines=_MAX_MONITOR_LINES,
                ):
                    parsed = _parse_response_line(raw, request_path)
                    if parsed is not None:
                        return parsed
        except TimeoutError:
            raise PortalError("portal-deadline-expired") from None
        except PortalError:
            raise
        except Exception:
            raise PortalError("portal-unavailable") from None
        raise PortalError("portal-unavailable")

    def _read_screenshot(self, uri: str) -> PortalScreenshot:
        path = _screenshot_path_from_uri(uri)
        payload = _read_bounded_regular_file(path, self._max_screenshot_bytes)
        _unlink_if_present(path)
        return PortalScreenshot(
            captured_at=self._now(),
            image_format="png",
            payload=payload,
        )


def _screenshot_path_from_uri(uri: str) -> str:
    if len(uri) > _MAX_URI_LENGTH:
        raise PortalError("portal-response-invalid")
    parsed = urlparse(uri)
    if parsed.scheme != "file":
        raise PortalError("portal-response-invalid")
    if parsed.netloc not in ("", _LOCALHOST_AUTHORITY):
        raise PortalError("portal-response-invalid")
    if parsed.query or parsed.fragment or not parsed.path:
        raise PortalError("portal-response-invalid")
    path = unquote(parsed.path)
    if not os.path.isabs(path) or ".." in path.split(os.sep) or "\x00" in path:
        raise PortalError("portal-response-invalid")
    return path


def _read_bounded_regular_file(path: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise PortalError("portal-response-invalid") from None
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            raise PortalError("portal-response-invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, max_bytes + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise PortalError("portal-response-oversized")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _unlink_if_present(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    except OSError:
        raise PortalError("portal-cleanup-failed") from None


def _parse_response_line(raw: bytes, request_path: str) -> tuple[int, object] | None:
    try:
        message: object = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(message, dict):
        return None
    typed = cast("dict[str, object]", message)
    if typed.get("member") != "Response" or typed.get("path") != request_path:
        return None
    payload = typed.get("payload")
    if not isinstance(payload, dict):
        raise PortalError("portal-response-invalid")
    typed_payload = cast("dict[str, object]", payload)
    if typed_payload.get("type") != "(ua{sv})":
        raise PortalError("portal-response-invalid")
    data = typed_payload.get("data")
    if not isinstance(data, list):
        raise PortalError("portal-response-invalid")
    typed_data = cast("list[object]", data)
    if len(typed_data) != 2:
        raise PortalError("portal-response-invalid")
    code = typed_data[0]
    results = typed_data[1]
    if isinstance(code, bool) or not isinstance(code, int):
        raise PortalError("portal-response-invalid")
    if not isinstance(results, dict):
        raise PortalError("portal-response-invalid")
    typed_results = cast("dict[str, object]", results)
    uri_variant = typed_results.get("uri")
    if uri_variant is None:
        return code, None
    if not isinstance(uri_variant, dict):
        raise PortalError("portal-response-invalid")
    variant = cast("dict[str, object]", uri_variant)
    if variant.get("type") != "s":
        raise PortalError("portal-response-invalid")
    uri = variant.get("data")
    if not isinstance(uri, str):
        raise PortalError("portal-response-invalid")
    return code, uri
