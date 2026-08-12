from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, TypeGuard, cast, runtime_checkable

from local_recall.config.models import MetadataSettings
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)

_SOURCE_ID = "qtile"
_ADAPTER_REVISION = "qtile-cmd-info-v1"
_MAX_WINDOW_ID = 0xFFFFFFFF
_MAX_SCREEN_INDEX = 0xFFFF
_DEFAULT_TIMEOUT_SECONDS = 0.5
_DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
_CONFIDENCE = {
    "application": 0.95,
    "layout": 0.98,
    "screen": 0.98,
    "window.id": 1.0,
    "window.title": 0.95,
    "workspace": 0.98,
}


class QtileMetadataFailureCode(StrEnum):
    NO_FOCUSED_WINDOW = "no-focused-window"
    EXECUTABLE_UNAVAILABLE = "executable-unavailable"
    RESTARTING = "restarting"
    IPC_FAILURE = "ipc-failure"
    FOCUS_CHANGED = "focus-changed"
    GROUP_CHANGED = "group-changed"
    INCONSISTENT_STATE = "inconsistent-state"
    WRONG_WINDOW = "wrong-window"
    MALFORMED_IDENTIFIER = "malformed-identifier"
    MALFORMED_RESPONSE = "malformed-response"
    UNSUPPORTED_RESPONSE = "unsupported-response"
    OUTPUT_TOO_LARGE = "output-too-large"
    TIMEOUT = "timeout"


class QtileAdapterFailure(RuntimeError):
    def __init__(self, code: QtileMetadataFailureCode) -> None:
        self.code = code
        super().__init__(f"Qtile adapter failed: {code.value}")


class QtileMetadataFailure(RuntimeError):
    def __init__(self, code: QtileMetadataFailureCode) -> None:
        self.code = code
        super().__init__(f"Qtile metadata collection failed: {code.value}")


class QtileCommand(StrEnum):
    STATUS = "status"
    WINDOW_INFO = "window-info"
    GROUP_INFO = "group-info"


_COMMAND_ARGUMENTS: Mapping[QtileCommand, tuple[str, ...]] = {
    QtileCommand.STATUS: ("cmd-obj", "-o", "cmd", "-f", "status"),
    QtileCommand.WINDOW_INFO: ("cmd-obj", "-o", "window", "-f", "info"),
    QtileCommand.GROUP_INFO: ("cmd-obj", "-o", "group", "-f", "info"),
}


@dataclass(frozen=True, slots=True, repr=False)
class QtileCommandResult:
    return_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(default=b"", repr=False)

    def __repr__(self) -> str:
        return (
            f"QtileCommandResult(return_code={self.return_code}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class QtileExecutablePath:
    path: Path | None

    def __post_init__(self) -> None:
        if self.path is not None and self.path.name != "qtile":
            raise ValueError("Qtile must use the fixed executable name")

    def __repr__(self) -> str:
        return f"QtileExecutablePath(configured={self.path is not None})"

    @classmethod
    def discover(
        cls,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> QtileExecutablePath:
        environment = os.environ if environ is None else environ
        resolved = shutil.which("qtile", path=environment.get("PATH"))
        return cls(Path(resolved).resolve() if resolved is not None else None)


@runtime_checkable
class QtileCommandRunner(Protocol):
    def executable_available(self) -> bool: ...

    async def run(
        self,
        command: QtileCommand,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> QtileCommandResult: ...


class FixedQtileCommandRunner:
    def __init__(
        self,
        executable: QtileExecutablePath | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._executable = executable or QtileExecutablePath.discover(environ=environ)
        self._environment = dict(os.environ if environ is None else environ)
        self._environment["LC_ALL"] = "C"
        self._environment["LANG"] = "C"

    def executable_available(self) -> bool:
        path = self._executable.path
        return bool(path is not None and path.is_file() and os.access(path, os.X_OK))

    async def run(
        self,
        command: QtileCommand,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> QtileCommandResult:
        if timeout_seconds <= 0.0 or max_output_bytes <= 0:
            raise ValueError("Qtile command bounds must be positive")
        path = self._executable.path
        if path is None or not self.executable_available():
            raise QtileAdapterFailure(QtileMetadataFailureCode.EXECUTABLE_UNAVAILABLE)
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(path),
                *_COMMAND_ARGUMENTS[command],
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._environment,
            )
        except OSError:
            raise QtileAdapterFailure(QtileMetadataFailureCode.EXECUTABLE_UNAVAILABLE) from None

        if process.stdout is None or process.stderr is None:
            process.kill()
            await process.wait()
            raise QtileAdapterFailure(QtileMetadataFailureCode.IPC_FAILURE)

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
            raise QtileAdapterFailure(QtileMetadataFailureCode.TIMEOUT) from None
        except _OutputLimitExceeded:
            await _terminate_process(process, tasks)
            raise QtileAdapterFailure(QtileMetadataFailureCode.OUTPUT_TOO_LARGE) from None
        except Exception:
            await _terminate_process(process, tasks)
            raise QtileAdapterFailure(QtileMetadataFailureCode.IPC_FAILURE) from None
        return QtileCommandResult(return_code, stdout, stderr)


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
class QtileSnapshot:
    window_id: int
    confirmed_window_id: int
    workspace: str = field(repr=False)
    confirmed_workspace: str = field(repr=False)
    application: str | None = field(default=None, repr=False)
    title: str | None = field(default=None, repr=False)
    layout: str | None = field(default=None, repr=False)
    confirmed_layout: str | None = field(default=None, repr=False)
    screen: int | None = None
    confirmed_screen: int | None = None

    def __post_init__(self) -> None:
        if not _valid_window_id(self.window_id) or not _valid_window_id(self.confirmed_window_id):
            raise ValueError("Qtile snapshot window identifier is invalid")
        for value, required, maximum in (
            (self.workspace, True, 256),
            (self.confirmed_workspace, True, 256),
            (self.application, False, 256),
            (self.title, False, 4096),
            (self.layout, False, 256),
            (self.confirmed_layout, False, 256),
        ):
            if value is None and not required:
                continue
            if not isinstance(value, str) or not value or "\x00" in value or len(value) > maximum:
                raise ValueError("Qtile snapshot text field is invalid")
        for value in (self.screen, self.confirmed_screen):
            if value is not None and (
                isinstance(value, bool) or not 0 <= value <= _MAX_SCREEN_INDEX
            ):
                raise ValueError("Qtile snapshot screen is invalid")

    def __repr__(self) -> str:
        return (
            "QtileSnapshot("
            f"window_id_valid={_valid_window_id(self.window_id)}, "
            f"window_confirmed={self.window_id == self.confirmed_window_id}, "
            f"application_present={self.application is not None}, "
            f"title_present={self.title is not None}, "
            f"workspace_confirmed={self.workspace == self.confirmed_workspace}, "
            f"layout_present={self.layout is not None}, "
            f"screen_present={self.screen is not None})"
        )


@runtime_checkable
class QtileSnapshotReader(Protocol):
    async def is_available(self) -> bool: ...

    async def snapshot(self, *, include_title: bool) -> QtileSnapshot: ...


@dataclass(frozen=True, slots=True, repr=False)
class _WindowInfo:
    window_id: int
    group: str = field(repr=False)
    application: str | None = field(default=None, repr=False)
    title: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _GroupInfo:
    name: str = field(repr=False)
    layout: str | None = field(default=None, repr=False)
    screen: int | None = None


class QtileCommandReader:
    def __init__(
        self,
        *,
        runner: QtileCommandRunner | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        if timeout_seconds <= 0.0 or max_output_bytes <= 0:
            raise ValueError("Qtile reader bounds must be positive")
        self._runner = runner or FixedQtileCommandRunner()
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    async def is_available(self) -> bool:
        if not self._runner.executable_available():
            return False
        try:
            result = await self._run(QtileCommand.STATUS)
            return result.return_code == 0 and _decode_json(result.stdout) == "OK"
        except Exception:
            return False

    async def snapshot(self, *, include_title: bool) -> QtileSnapshot:
        initial_window = await self._window_info(
            include_title=include_title,
            absent_code=QtileMetadataFailureCode.NO_FOCUSED_WINDOW,
        )
        initial_group = await self._group_info()
        if initial_window.group != initial_group.name:
            raise QtileAdapterFailure(QtileMetadataFailureCode.WRONG_WINDOW)

        final_group = await self._group_info()
        final_window = await self._window_info(
            include_title=False,
            absent_code=QtileMetadataFailureCode.FOCUS_CHANGED,
        )
        if final_window.group != final_group.name:
            raise QtileAdapterFailure(QtileMetadataFailureCode.WRONG_WINDOW)

        return QtileSnapshot(
            window_id=initial_window.window_id,
            confirmed_window_id=final_window.window_id,
            application=initial_window.application,
            title=initial_window.title if include_title else None,
            workspace=initial_group.name,
            confirmed_workspace=final_group.name,
            layout=initial_group.layout,
            confirmed_layout=final_group.layout,
            screen=initial_group.screen,
            confirmed_screen=final_group.screen,
        )

    async def _window_info(
        self,
        *,
        include_title: bool,
        absent_code: QtileMetadataFailureCode,
    ) -> _WindowInfo:
        result = await self._run(QtileCommand.WINDOW_INFO)
        if result.return_code != 0:
            await self._raise_for_failed_command(absent_code)
        value = _decode_object(result.stdout)
        _require_supported_response(value)
        window_id = value.get("id")
        if not _valid_window_id(window_id):
            raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_IDENTIFIER)
        group = _required_text(value.get("group"), max_length=256)
        application = _application(value.get("wm_class"))
        title = _optional_text(value.get("name"), max_length=4096) if include_title else None
        return _WindowInfo(window_id, group, application, title)

    async def _group_info(self) -> _GroupInfo:
        result = await self._run(QtileCommand.GROUP_INFO)
        if result.return_code != 0:
            await self._raise_for_failed_command(QtileMetadataFailureCode.IPC_FAILURE)
        value = _decode_object(result.stdout)
        _require_supported_response(value)
        name = _required_text(value.get("name"), max_length=256)
        layout = _optional_text(value.get("layout"), max_length=256)
        screen = _optional_screen(value.get("screen"))
        return _GroupInfo(name, layout, screen)

    async def _raise_for_failed_command(self, healthy_code: QtileMetadataFailureCode) -> None:
        status = await self._run(QtileCommand.STATUS)
        if status.return_code == 0 and _decode_json(status.stdout) == "OK":
            raise QtileAdapterFailure(healthy_code)
        raise QtileAdapterFailure(QtileMetadataFailureCode.RESTARTING)

    async def _run(self, command: QtileCommand) -> QtileCommandResult:
        return await self._runner.run(
            command,
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )


def _decode_json(payload: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value

    try:
        return cast(
            object,
            json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates),
        )
    except UnicodeDecodeError, ValueError, json.JSONDecodeError:
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE) from None


def _decode_object(payload: bytes) -> dict[str, object]:
    value = _decode_json(payload)
    if not isinstance(value, dict):
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE)
    return cast(dict[str, object], value)


def _require_supported_response(value: Mapping[str, object]) -> None:
    version = value.get("response_version")
    if version is not None and version != 1:
        raise QtileAdapterFailure(QtileMetadataFailureCode.UNSUPPORTED_RESPONSE)


def _valid_window_id(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_WINDOW_ID


def _required_text(value: object, *, max_length: int) -> str:
    normalized = _optional_text(value, max_length=max_length)
    if normalized is None:
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE)
    return normalized


def _optional_text(value: object, *, max_length: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE)
    normalized = " ".join(value.split())
    if not normalized:
        return None
    if len(normalized) > max_length:
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE)
    return normalized


def _application(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE)
    items = cast(list[object], value)
    if not 1 <= len(items) <= 2:
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE)
    parts = tuple(_optional_text(item, max_length=256) for item in items)
    selected = parts[1] if len(parts) == 2 and parts[1] is not None else parts[0]
    return selected.casefold() if selected is not None else None


def _optional_screen(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_SCREEN_INDEX:
        raise QtileAdapterFailure(QtileMetadataFailureCode.MALFORMED_RESPONSE)
    return value


class QtileMetadataSource:
    def __init__(
        self,
        settings: MetadataSettings | None = None,
        *,
        reader: QtileSnapshotReader | None = None,
        now: Callable[[], datetime] | None = None,
        monotonic_ns: Callable[[], int] | None = None,
        max_attempts: int = 2,
    ) -> None:
        if not 1 <= max_attempts <= 3:
            raise ValueError("Qtile metadata attempts must be between one and three")
        self._settings = settings or MetadataSettings()
        self._reader = reader or QtileCommandReader()
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
        last_code = QtileMetadataFailureCode.RESTARTING
        for attempt in range(self._max_attempts):
            self._require_deadline(request)
            include_title = self._settings.window_titles_enabled and (
                not request.requested_fields or "window.title" in request.requested_fields
            )
            try:
                snapshot = await self._reader.snapshot(include_title=include_title)
                inconsistency = _snapshot_inconsistency(snapshot)
                if inconsistency is not None:
                    last_code = inconsistency
                    if attempt + 1 < self._max_attempts:
                        continue
                    raise QtileMetadataFailure(inconsistency)
                self._require_deadline(request)
                return self._metadata(snapshot, request, include_title=include_title)
            except QtileMetadataFailure:
                raise
            except QtileAdapterFailure as exc:
                last_code = exc.code
                if (
                    exc.code
                    in {
                        QtileMetadataFailureCode.RESTARTING,
                        QtileMetadataFailureCode.IPC_FAILURE,
                        QtileMetadataFailureCode.FOCUS_CHANGED,
                        QtileMetadataFailureCode.GROUP_CHANGED,
                        QtileMetadataFailureCode.INCONSISTENT_STATE,
                    }
                    and attempt + 1 < self._max_attempts
                ):
                    continue
                raise QtileMetadataFailure(exc.code) from None
            except Exception:
                last_code = QtileMetadataFailureCode.IPC_FAILURE
                if attempt + 1 < self._max_attempts:
                    continue
                raise QtileMetadataFailure(last_code) from None
        raise QtileMetadataFailure(last_code)

    def _require_deadline(self, request: MetadataRequest) -> None:
        if self._monotonic_ns() >= request.deadline_monotonic_ns:
            raise QtileMetadataFailure(QtileMetadataFailureCode.TIMEOUT)

    def _metadata(
        self,
        snapshot: QtileSnapshot,
        request: MetadataRequest,
        *,
        include_title: bool,
    ) -> ContextMetadata:
        observed_at = self._now()
        values: dict[str, str | int | None] = {
            "application": snapshot.application,
            "layout": snapshot.layout,
            "screen": snapshot.screen,
            "window.id": snapshot.window_id,
            "window.title": snapshot.title if include_title else None,
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


def _snapshot_inconsistency(snapshot: QtileSnapshot) -> QtileMetadataFailureCode | None:
    if snapshot.window_id != snapshot.confirmed_window_id:
        return QtileMetadataFailureCode.FOCUS_CHANGED
    if snapshot.workspace != snapshot.confirmed_workspace:
        return QtileMetadataFailureCode.GROUP_CHANGED
    if snapshot.layout != snapshot.confirmed_layout or snapshot.screen != snapshot.confirmed_screen:
        return QtileMetadataFailureCode.INCONSISTENT_STATE
    return None
