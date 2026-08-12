from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from local_recall.config.models import MetadataSettings
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)

_SOURCE_ID = "xorg-generic"
_ADAPTER_REVISION = "ewmh-xprop-v1"
_MAX_WINDOW_ID = 0xFFFFFFFF
_DEFAULT_TIMEOUT_SECONDS = 0.5
_DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
_ACTIVE_WINDOW = re.compile(r"^_NET_ACTIVE_WINDOW\s*(?:=|:)\s*window id # (0x[0-9a-fA-F]+)\s*$")
_PROPERTY_LINE = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$")
_MISSING_PROPERTY_LINE = re.compile(r"^([A-Z_][A-Z0-9_]*):\s*(.*)$")
_XWININFO_WINDOW = re.compile(r"^xwininfo: Window id: (0x[0-9a-fA-F]+)(?:\s.*)?$")
_XWININFO_INTEGER = {
    "x": re.compile(r"^\s*Absolute upper-left X:\s*(-?[0-9]+)\s*$"),
    "y": re.compile(r"^\s*Absolute upper-left Y:\s*(-?[0-9]+)\s*$"),
    "width": re.compile(r"^\s*Width:\s*([0-9]+)\s*$"),
    "height": re.compile(r"^\s*Height:\s*([0-9]+)\s*$"),
}
_CONFIDENCE = {
    "application": 0.9,
    "window.height": 0.95,
    "window.id": 1.0,
    "window.title": 0.9,
    "window.width": 0.95,
    "window.x": 0.95,
    "window.y": 0.95,
    "workspace": 0.9,
}


class XorgMetadataFailureCode(StrEnum):
    NO_ACTIVE_WINDOW = "no-active-window"
    MALFORMED_ACTIVE_WINDOW = "malformed-active-window"
    WINDOW_UNAVAILABLE = "window-unavailable"
    WRONG_WINDOW = "wrong-window"
    FOCUS_CHANGED = "focus-changed"
    MALFORMED_PROPERTY = "malformed-property"
    OUTPUT_TOO_LARGE = "output-too-large"
    TIMEOUT = "timeout"
    EXECUTABLE_UNAVAILABLE = "executable-unavailable"
    EXECUTION_FAILED = "execution-failed"


class XorgAdapterFailure(RuntimeError):
    def __init__(self, code: XorgMetadataFailureCode) -> None:
        self.code = code
        super().__init__(f"Xorg adapter failed: {code.value}")


class XorgMetadataFailure(RuntimeError):
    def __init__(self, code: XorgMetadataFailureCode) -> None:
        self.code = code
        super().__init__(f"Xorg metadata collection failed: {code.value}")


class XorgCommand(StrEnum):
    XPROP = "xprop"
    XWININFO = "xwininfo"


@dataclass(frozen=True, slots=True, repr=False)
class XorgCommandResult:
    return_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(default=b"", repr=False)

    def __repr__(self) -> str:
        return (
            f"XorgCommandResult(return_code={self.return_code}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class XorgExecutablePaths:
    xprop: Path | None
    xwininfo: Path | None = None

    def __post_init__(self) -> None:
        for path, expected in (
            (self.xprop, XorgCommand.XPROP.value),
            (self.xwininfo, XorgCommand.XWININFO.value),
        ):
            if path is not None and path.name != expected:
                raise ValueError(f"{expected} must use the fixed executable name")

    def __repr__(self) -> str:
        return (
            "XorgExecutablePaths("
            f"xprop_configured={self.xprop is not None}, "
            f"xwininfo_configured={self.xwininfo is not None})"
        )

    @classmethod
    def discover(
        cls,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> XorgExecutablePaths:
        environment = os.environ if environ is None else environ
        search_path = environment.get("PATH")
        return cls(
            xprop=_discover_executable(XorgCommand.XPROP.value, search_path),
            xwininfo=_discover_executable(XorgCommand.XWININFO.value, search_path),
        )


def _discover_executable(name: str, search_path: str | None) -> Path | None:
    resolved = shutil.which(name, path=search_path)
    return Path(resolved).resolve() if resolved is not None else None


@runtime_checkable
class XorgCommandRunner(Protocol):
    def is_available(self, command: XorgCommand) -> bool: ...

    async def run(
        self,
        command: XorgCommand,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> XorgCommandResult: ...


class FixedXorgCommandRunner:
    def __init__(
        self,
        executables: XorgExecutablePaths | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._executables = executables or XorgExecutablePaths.discover(environ=environ)
        self._environment = dict(os.environ if environ is None else environ)
        self._environment["LC_ALL"] = "C"
        self._environment["LANG"] = "C"

    def is_available(self, command: XorgCommand) -> bool:
        executable = self._executable(command)
        return bool(
            executable is not None and executable.is_file() and os.access(executable, os.X_OK)
        )

    async def run(
        self,
        command: XorgCommand,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> XorgCommandResult:
        if timeout_seconds <= 0.0 or max_output_bytes <= 0:
            raise ValueError("Xorg command bounds must be positive")
        executable = self._executable(command)
        if executable is None or not self.is_available(command):
            raise XorgAdapterFailure(XorgMetadataFailureCode.EXECUTABLE_UNAVAILABLE)
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(executable),
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._environment,
            )
        except OSError:
            raise XorgAdapterFailure(XorgMetadataFailureCode.EXECUTABLE_UNAVAILABLE) from None

        if process.stdout is None or process.stderr is None:
            process.kill()
            await process.wait()
            raise XorgAdapterFailure(XorgMetadataFailureCode.EXECUTION_FAILED)

        stdout_task = asyncio.create_task(_read_bounded(process.stdout, max_output_bytes))
        stderr_task = asyncio.create_task(_read_bounded(process.stderr, max_output_bytes))
        wait_task = asyncio.create_task(process.wait())
        tasks = (stdout_task, stderr_task, wait_task)
        try:
            stdout, stderr, return_code = await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            await _terminate_process(process, tasks)
            raise XorgAdapterFailure(XorgMetadataFailureCode.TIMEOUT) from None
        except _OutputLimitExceeded:
            await _terminate_process(process, tasks)
            raise XorgAdapterFailure(XorgMetadataFailureCode.OUTPUT_TOO_LARGE) from None
        except Exception:
            await _terminate_process(process, tasks)
            raise XorgAdapterFailure(XorgMetadataFailureCode.EXECUTION_FAILED) from None
        return XorgCommandResult(return_code, stdout, stderr)

    def _executable(self, command: XorgCommand) -> Path | None:
        if command is XorgCommand.XPROP:
            return self._executables.xprop
        return self._executables.xwininfo


class _OutputLimitExceeded(RuntimeError):
    pass


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


async def _terminate_process(
    process: asyncio.subprocess.Process,
    tasks: tuple[asyncio.Task[bytes], asyncio.Task[bytes], asyncio.Task[int]],
) -> None:
    if process.returncode is None:
        process.kill()
    await process.wait()
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@dataclass(frozen=True, slots=True, repr=False)
class XorgWindowProperties:
    window_id: int
    application: str | None = field(default=None, repr=False)
    title: str | None = field(default=None, repr=False)
    x: int | None = None
    y: int | None = None
    width: int | None = None
    height: int | None = None
    workspace: int | None = None

    def __post_init__(self) -> None:
        _validate_window_id(self.window_id, XorgMetadataFailureCode.WRONG_WINDOW)
        geometry = (self.x, self.y, self.width, self.height)
        if any(value is None for value in geometry) and any(
            value is not None for value in geometry
        ):
            raise ValueError("Xorg geometry must be complete or unavailable")
        if self.width is not None and self.width <= 0:
            raise ValueError("Xorg window width must be positive")
        if self.height is not None and self.height <= 0:
            raise ValueError("Xorg window height must be positive")

    def __repr__(self) -> str:
        return (
            "XorgWindowProperties("
            f"window_id_valid={0 < self.window_id <= _MAX_WINDOW_ID}, "
            f"application_present={self.application is not None}, "
            f"title_present={self.title is not None}, "
            f"geometry_present={self.x is not None}, "
            f"workspace_present={self.workspace is not None})"
        )


@runtime_checkable
class XorgPropertyReader(Protocol):
    async def is_available(self) -> bool: ...

    async def active_window_id(self) -> int | None: ...

    async def window_properties(
        self,
        window_id: int,
        *,
        include_title: bool,
    ) -> XorgWindowProperties: ...


class XpropXorgPropertyReader:
    def __init__(
        self,
        *,
        runner: XorgCommandRunner | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        if timeout_seconds <= 0.0 or max_output_bytes <= 0:
            raise ValueError("Xorg reader bounds must be positive")
        self._runner = runner or FixedXorgCommandRunner()
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    async def is_available(self) -> bool:
        return self._runner.is_available(XorgCommand.XPROP)

    async def active_window_id(self) -> int | None:
        result = await self._run(
            XorgCommand.XPROP,
            ("-root", "-notype", "_NET_ACTIVE_WINDOW"),
        )
        if result.return_code != 0:
            raise XorgAdapterFailure(XorgMetadataFailureCode.EXECUTION_FAILED)
        try:
            text = result.stdout.decode("utf-8")
            stripped = text.strip()
            match = _ACTIVE_WINDOW.fullmatch(stripped)
            if match is None:
                missing = _MISSING_PROPERTY_LINE.fullmatch(stripped)
                if (
                    missing is not None
                    and missing.group(1) == "_NET_ACTIVE_WINDOW"
                    and any(
                        reason in missing.group(2).casefold()
                        for reason in ("not found", "no such atom")
                    )
                ):
                    return None
                raise ValueError
            window_id = int(match.group(1), 16)
            if window_id == 0:
                return None
            _validate_window_id(
                window_id,
                XorgMetadataFailureCode.MALFORMED_ACTIVE_WINDOW,
            )
            return window_id
        except UnicodeDecodeError, ValueError:
            raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_ACTIVE_WINDOW) from None

    async def window_properties(
        self,
        window_id: int,
        *,
        include_title: bool,
    ) -> XorgWindowProperties:
        _validate_window_id(window_id, XorgMetadataFailureCode.MALFORMED_ACTIVE_WINDOW)
        property_names = ["WM_CLASS"]
        if include_title:
            property_names.extend(("_NET_WM_NAME", "WM_NAME"))
        property_names.append("_NET_WM_DESKTOP")
        result = await self._run(
            XorgCommand.XPROP,
            ("-id", _format_window_id(window_id), "-notype", *property_names),
        )
        if result.return_code != 0:
            raise XorgAdapterFailure(XorgMetadataFailureCode.WINDOW_UNAVAILABLE)
        values = _parse_window_properties(result.stdout, frozenset(property_names))

        geometry: tuple[int | None, int | None, int | None, int | None] = (
            None,
            None,
            None,
            None,
        )
        if self._runner.is_available(XorgCommand.XWININFO):
            geometry_result = await self._run(
                XorgCommand.XWININFO,
                ("-id", _format_window_id(window_id), "-stats"),
            )
            if geometry_result.return_code != 0:
                raise XorgAdapterFailure(XorgMetadataFailureCode.WINDOW_UNAVAILABLE)
            geometry = _parse_geometry(geometry_result.stdout, window_id)

        return XorgWindowProperties(
            window_id=window_id,
            application=_application_value(values.get("WM_CLASS")),
            title=_title_value(values) if include_title else None,
            x=geometry[0],
            y=geometry[1],
            width=geometry[2],
            height=geometry[3],
            workspace=_workspace_value(values.get("_NET_WM_DESKTOP")),
        )

    async def _run(
        self,
        command: XorgCommand,
        args: tuple[str, ...],
    ) -> XorgCommandResult:
        return await self._runner.run(
            command,
            args,
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )


def _validate_window_id(window_id: int, code: XorgMetadataFailureCode) -> None:
    if isinstance(window_id, bool) or not 0 < window_id <= _MAX_WINDOW_ID:
        raise XorgAdapterFailure(code)


def _format_window_id(window_id: int) -> str:
    return f"0x{window_id:08x}"


def _parse_window_properties(
    payload: bytes,
    expected_names: frozenset[str],
) -> dict[str, str | None]:
    try:
        text = payload.decode("utf-8")
        values: dict[str, str | None] = {}
        for line in text.splitlines():
            property_match = _PROPERTY_LINE.fullmatch(line)
            missing_match = _MISSING_PROPERTY_LINE.fullmatch(line)
            match = property_match or missing_match
            if match is None:
                raise ValueError
            name = match.group(1)
            if name not in expected_names or name in values:
                raise ValueError
            if property_match is not None:
                values[name] = match.group(2).strip()
                continue
            reason = match.group(2).casefold()
            if "not found" not in reason and "no such atom" not in reason:
                raise ValueError
            values[name] = None
        if set(values) != set(expected_names):
            raise ValueError
        return values
    except UnicodeDecodeError, ValueError:
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY) from None


def _application_value(raw: str | None) -> str | None:
    if raw is None:
        return None
    values = _quoted_values(raw)
    if len(values) != 2:
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
    selected = values[1] or values[0]
    return _normalize_text(selected, max_length=256, casefold=True)


def _title_value(values: Mapping[str, str | None]) -> str | None:
    raw = values.get("_NET_WM_NAME") or values.get("WM_NAME")
    if raw is None:
        return None
    parsed = _quoted_values(raw)
    if len(parsed) != 1:
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
    return _normalize_text(parsed[0], max_length=4096, casefold=False)


def _workspace_value(raw: str | None) -> int | None:
    if raw is None:
        return None
    if not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", raw):
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
    value = int(raw, 0)
    if not 0 <= value <= _MAX_WINDOW_ID:
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
    return value


def _quoted_values(raw: str) -> tuple[str, ...]:
    values: list[str] = []
    index = 0
    length = len(raw)
    while index < length:
        while index < length and raw[index].isspace():
            index += 1
        if index >= length or raw[index] != '"':
            raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
        index += 1
        characters: list[str] = []
        while index < length and raw[index] != '"':
            if raw[index] != "\\":
                characters.append(raw[index])
                index += 1
                continue
            index += 1
            if index >= length:
                raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
            escaped = raw[index]
            simple = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}
            if escaped in simple:
                characters.append(simple[escaped])
                index += 1
                continue
            if escaped in "01234567":
                end = index + 1
                while end < min(index + 3, length) and raw[end] in "01234567":
                    end += 1
                characters.append(chr(int(raw[index:end], 8)))
                index = end
                continue
            raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
        if index >= length:
            raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
        values.append("".join(characters))
        index += 1
        while index < length and raw[index].isspace():
            index += 1
        if index >= length:
            break
        if raw[index] != ",":
            raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
        index += 1
    return tuple(values)


def _normalize_text(value: str, *, max_length: int, casefold: bool) -> str | None:
    if "\x00" in value:
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
    normalized = " ".join(value.split())
    if not normalized:
        return None
    if len(normalized) > max_length:
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY)
    return normalized.casefold() if casefold else normalized


def _parse_geometry(
    payload: bytes,
    expected_window_id: int,
) -> tuple[int, int, int, int]:
    try:
        text = payload.decode("utf-8")
        window_id: int | None = None
        values: dict[str, int] = {}
        for line in text.splitlines():
            window_match = _XWININFO_WINDOW.fullmatch(line)
            if window_match is not None:
                if window_id is not None:
                    raise ValueError
                window_id = int(window_match.group(1), 16)
                continue
            for name, pattern in _XWININFO_INTEGER.items():
                match = pattern.fullmatch(line)
                if match is None:
                    continue
                if name in values:
                    raise ValueError
                values[name] = int(match.group(1))
                break
        if window_id != expected_window_id:
            raise XorgAdapterFailure(XorgMetadataFailureCode.WRONG_WINDOW)
        if set(values) != set(_XWININFO_INTEGER):
            raise ValueError
        if values["width"] <= 0 or values["height"] <= 0:
            raise ValueError
        if not all(-(2**31) <= values[name] < 2**31 for name in ("x", "y")):
            raise ValueError
        return values["x"], values["y"], values["width"], values["height"]
    except XorgAdapterFailure:
        raise
    except UnicodeDecodeError, ValueError:
        raise XorgAdapterFailure(XorgMetadataFailureCode.MALFORMED_PROPERTY) from None


class GenericXorgMetadataSource:
    def __init__(
        self,
        settings: MetadataSettings | None = None,
        *,
        reader: XorgPropertyReader | None = None,
        now: Callable[[], datetime] | None = None,
        monotonic_ns: Callable[[], int] | None = None,
        max_attempts: int = 2,
    ) -> None:
        if not 1 <= max_attempts <= 3:
            raise ValueError("Xorg metadata attempts must be between one and three")
        self._settings = settings or MetadataSettings()
        self._reader = reader or XpropXorgPropertyReader()
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic_ns = monotonic_ns or time.monotonic_ns
        self._max_attempts = max_attempts

    @property
    def source_id(self) -> str:
        return _SOURCE_ID

    async def is_available(self) -> bool:
        try:
            return await self._reader.is_available()
        except Exception:
            return False

    async def collect(self, request: MetadataRequest) -> ContextMetadata:
        last_code = XorgMetadataFailureCode.FOCUS_CHANGED
        for attempt in range(self._max_attempts):
            self._require_deadline(request)
            try:
                initial_window = await self._reader.active_window_id()
                if initial_window is None:
                    raise XorgMetadataFailure(XorgMetadataFailureCode.NO_ACTIVE_WINDOW)
                include_title = self._settings.window_titles_enabled and (
                    not request.requested_fields or "window.title" in request.requested_fields
                )
                snapshot = await self._reader.window_properties(
                    initial_window,
                    include_title=include_title,
                )
                if snapshot.window_id != initial_window:
                    raise XorgMetadataFailure(XorgMetadataFailureCode.WRONG_WINDOW)
                final_window = await self._reader.active_window_id()
                if final_window != initial_window:
                    last_code = XorgMetadataFailureCode.FOCUS_CHANGED
                    continue
                self._require_deadline(request)
                return self._metadata(snapshot, request, include_title=include_title)
            except XorgMetadataFailure:
                raise
            except XorgAdapterFailure as exc:
                last_code = exc.code
                if (
                    exc.code is XorgMetadataFailureCode.WINDOW_UNAVAILABLE
                    and attempt + 1 < self._max_attempts
                ):
                    continue
                raise XorgMetadataFailure(exc.code) from None
            except Exception:
                raise XorgMetadataFailure(XorgMetadataFailureCode.EXECUTION_FAILED) from None
        raise XorgMetadataFailure(last_code)

    def _require_deadline(self, request: MetadataRequest) -> None:
        if self._monotonic_ns() >= request.deadline_monotonic_ns:
            raise XorgMetadataFailure(XorgMetadataFailureCode.TIMEOUT)

    def _metadata(
        self,
        snapshot: XorgWindowProperties,
        request: MetadataRequest,
        *,
        include_title: bool,
    ) -> ContextMetadata:
        observed_at = self._now()
        values: dict[str, str | int | None] = {
            "application": snapshot.application,
            "window.height": snapshot.height,
            "window.id": snapshot.window_id,
            "window.title": snapshot.title if include_title else None,
            "window.width": snapshot.width,
            "window.x": snapshot.x,
            "window.y": snapshot.y,
            "workspace": snapshot.workspace,
        }
        requested = request.requested_fields
        fields = tuple(
            ContextField(
                name=name,
                value=values[name],
                provenance=(
                    MetadataProvenance(
                        source_id=self.source_id,
                        observed_at=observed_at,
                        confidence=SourceConfidence(_CONFIDENCE[name]),
                        adapter_revision=_ADAPTER_REVISION,
                    ),
                ),
            )
            for name in sorted(values)
            if values[name] is not None and (not requested or name in requested)
        )
        return ContextMetadata(observed_at=observed_at, fields=fields)
