from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.config import MetadataSettings
from local_recall.domain.capture import MetadataRequest
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.metadata import (
    FixedXorgCommandRunner,
    GenericXorgMetadataSource,
    XorgAdapterFailure,
    XorgCommand,
    XorgCommandResult,
    XorgExecutablePaths,
    XorgMetadataFailure,
    XorgMetadataFailureCode,
    XorgWindowProperties,
    XpropXorgPropertyReader,
)

NOW = datetime(2026, 8, 12, 1, 2, 3, tzinfo=UTC)
WINDOW_ID = 0x2A00007


def request(*requested_fields: str) -> MetadataRequest:
    return MetadataRequest(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=time.monotonic_ns() + 10_000_000_000,
        requested_fields=frozenset(requested_fields),
    )


def properties(**overrides: object) -> XorgWindowProperties:
    values: dict[str, object] = {
        "window_id": WINDOW_ID,
        "application": "synthetic-app",
        "title": "Synthetic title",
        "x": -1920,
        "y": 24,
        "width": 1280,
        "height": 720,
        "workspace": 3,
    }
    values.update(overrides)
    return XorgWindowProperties(**values)  # type: ignore[arg-type]


@dataclass
class SyntheticReader:
    active_windows: list[int | None]
    snapshots: list[XorgWindowProperties | Exception]
    available: bool = True
    active_calls: int = 0
    property_calls: list[tuple[int, bool]] = field(default_factory=lambda: list[tuple[int, bool]]())

    async def is_available(self) -> bool:
        return self.available

    async def active_window_id(self) -> int | None:
        index = min(self.active_calls, len(self.active_windows) - 1)
        self.active_calls += 1
        return self.active_windows[index]

    async def window_properties(
        self, window_id: int, *, include_title: bool
    ) -> XorgWindowProperties:
        self.property_calls.append((window_id, include_title))
        item = self.snapshots.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def collect(
    reader: SyntheticReader,
    *,
    titles: bool = False,
    max_attempts: int = 2,
    metadata_request: MetadataRequest | None = None,
):
    source = GenericXorgMetadataSource(
        MetadataSettings(window_titles_enabled=titles),
        reader=reader,
        now=lambda: NOW,
        max_attempts=max_attempts,
    )
    return asyncio.run(source.collect(metadata_request or request()))


def test_collects_stable_ewmh_window_in_canonical_field_order() -> None:
    reader = SyntheticReader([WINDOW_ID, WINDOW_ID], [properties()])

    metadata = collect(reader, titles=True)

    assert tuple(field.name for field in metadata.fields) == (
        "application",
        "window.height",
        "window.id",
        "window.title",
        "window.width",
        "window.x",
        "window.y",
        "workspace",
    )
    assert metadata.observed_at == NOW
    assert metadata.get("application") == "synthetic-app"
    assert metadata.get("window.id") == WINDOW_ID
    assert metadata.get("window.x") == -1920
    assert metadata.get("window.y") == 24
    assert metadata.get("window.width") == 1280
    assert metadata.get("window.height") == 720
    assert metadata.get("workspace") == 3
    assert metadata.get("window.title") == "Synthetic title"
    assert reader.property_calls == [(WINDOW_ID, True)]


def test_title_collection_is_disabled_independently_by_default() -> None:
    reader = SyntheticReader([WINDOW_ID, WINDOW_ID], [properties()])

    metadata = collect(reader)

    assert metadata.get("window.title") is None
    assert reader.property_calls == [(WINDOW_ID, False)]


def test_requested_fields_can_omit_title_even_when_enabled() -> None:
    reader = SyntheticReader([WINDOW_ID, WINDOW_ID], [properties()])

    metadata = collect(
        reader,
        titles=True,
        metadata_request=request("application", "workspace"),
    )

    assert tuple(field.name for field in metadata.fields) == ("application", "workspace")
    assert reader.property_calls == [(WINDOW_ID, False)]


def test_missing_optional_properties_are_omitted() -> None:
    reader = SyntheticReader(
        [WINDOW_ID, WINDOW_ID],
        [
            properties(
                application=None,
                title=None,
                x=None,
                y=None,
                width=None,
                height=None,
                workspace=None,
            )
        ],
    )

    metadata = collect(reader, titles=True)

    assert tuple(field.name for field in metadata.fields) == ("window.id",)


def test_every_field_has_stable_provenance_and_confidence() -> None:
    metadata = collect(
        SyntheticReader([WINDOW_ID, WINDOW_ID], [properties()]),
        titles=True,
    )

    for context_field in metadata.fields:
        assert len(context_field.provenance) == 1
        provenance = context_field.provenance[0]
        assert provenance.source_id == "xorg-generic"
        assert provenance.observed_at == NOW
        assert provenance.adapter_revision == "ewmh-xprop-v1"
        assert 0.0 < provenance.confidence.value <= 1.0


def test_no_active_window_is_a_typed_sanitized_failure() -> None:
    reader = SyntheticReader([None], [properties()])

    with pytest.raises(XorgMetadataFailure) as captured:
        collect(reader)

    assert captured.value.code is XorgMetadataFailureCode.NO_ACTIVE_WINDOW
    assert reader.property_calls == []


def test_focus_change_once_retries_without_mixing_windows() -> None:
    second_window = WINDOW_ID + 1
    reader = SyntheticReader(
        [WINDOW_ID, second_window, second_window, second_window],
        [properties(), properties(window_id=second_window, application="second-app")],
    )

    metadata = collect(reader)

    assert metadata.get("window.id") == second_window
    assert metadata.get("application") == "second-app"
    assert reader.property_calls == [(WINDOW_ID, False), (second_window, False)]


def test_repeated_focus_churn_exhausts_fixed_retry_budget() -> None:
    reader = SyntheticReader(
        [WINDOW_ID, WINDOW_ID + 1, WINDOW_ID + 2, WINDOW_ID + 3],
        [properties(), properties(window_id=WINDOW_ID + 2)],
    )

    with pytest.raises(XorgMetadataFailure) as captured:
        collect(reader, max_attempts=2)

    assert captured.value.code is XorgMetadataFailureCode.FOCUS_CHANGED


def test_destroyed_window_retries_then_fails_cleanly() -> None:
    failure = XorgAdapterFailure(XorgMetadataFailureCode.WINDOW_UNAVAILABLE)
    reader = SyntheticReader(
        [WINDOW_ID, WINDOW_ID],
        [failure, XorgAdapterFailure(XorgMetadataFailureCode.WINDOW_UNAVAILABLE)],
    )

    with pytest.raises(XorgMetadataFailure) as captured:
        collect(reader, max_attempts=2)

    assert captured.value.code is XorgMetadataFailureCode.WINDOW_UNAVAILABLE


def test_reader_rejects_snapshot_for_wrong_window() -> None:
    marker = "sensitive-wrong-window-value"
    reader = SyntheticReader(
        [WINDOW_ID, WINDOW_ID],
        [properties(window_id=WINDOW_ID + 1, title=marker)],
    )

    with pytest.raises(XorgMetadataFailure) as captured:
        collect(reader, titles=True)

    assert captured.value.code is XorgMetadataFailureCode.WRONG_WINDOW
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)


def test_adapter_failure_messages_never_retain_exception_content() -> None:
    marker = "sensitive-adapter-exception"
    failure = RuntimeError(marker)
    reader = SyntheticReader([WINDOW_ID], [failure])

    with pytest.raises(XorgMetadataFailure) as captured:
        collect(reader, max_attempts=1)

    assert captured.value.code is XorgMetadataFailureCode.EXECUTION_FAILED
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)


@dataclass
class SyntheticCommandRunner:
    results: list[XorgCommandResult | XorgAdapterFailure]
    available_commands: frozenset[XorgCommand] = frozenset({XorgCommand.XPROP})
    calls: list[tuple[XorgCommand, tuple[str, ...]]] = field(
        default_factory=lambda: list[tuple[XorgCommand, tuple[str, ...]]]()
    )

    def is_available(self, command: XorgCommand) -> bool:
        return command in self.available_commands

    async def run(
        self,
        command: XorgCommand,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> XorgCommandResult:
        del timeout_seconds, max_output_bytes
        self.calls.append((command, args))
        item = self.results.pop(0)
        if isinstance(item, XorgAdapterFailure):
            raise item
        return item


def command_result(stdout: str, return_code: int = 0) -> XorgCommandResult:
    return XorgCommandResult(return_code=return_code, stdout=stdout.encode(), stderr=b"")


def test_xprop_reader_parses_application_title_and_workspace_strictly() -> None:
    runner = SyntheticCommandRunner(
        [
            command_result("_NET_ACTIVE_WINDOW: window id # 0x2a00007\n"),
            command_result(
                'WM_CLASS = "synthetic-instance", "Synthetic-App"\n'
                '_NET_WM_NAME = "Synthetic title"\n'
                "WM_NAME:  not found.\n"
                "_NET_WM_DESKTOP = 3\n"
            ),
        ]
    )
    reader = XpropXorgPropertyReader(runner=runner)

    window_id = asyncio.run(reader.active_window_id())
    snapshot = asyncio.run(reader.window_properties(window_id or 0, include_title=True))

    assert window_id == WINDOW_ID
    assert snapshot.application == "synthetic-app"
    assert snapshot.title == "Synthetic title"
    assert snapshot.workspace == 3
    assert snapshot.x is None
    assert runner.calls[1] == (
        XorgCommand.XPROP,
        (
            "-id",
            "0x02a00007",
            "-notype",
            "WM_CLASS",
            "_NET_WM_NAME",
            "WM_NAME",
            "_NET_WM_DESKTOP",
        ),
    )


def test_xprop_reader_omits_title_properties_when_disabled() -> None:
    runner = SyntheticCommandRunner(
        [command_result('WM_CLASS = "instance", "App"\n_NET_WM_DESKTOP: not found.\n')]
    )
    reader = XpropXorgPropertyReader(runner=runner)

    snapshot = asyncio.run(reader.window_properties(WINDOW_ID, include_title=False))

    assert snapshot.title is None
    assert "_NET_WM_NAME" not in runner.calls[0][1]
    assert "WM_NAME" not in runner.calls[0][1]


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (
            "_NET_ACTIVE_WINDOW = window id # 0xnothex\n",
            XorgMetadataFailureCode.MALFORMED_ACTIVE_WINDOW,
        ),
        (
            "_NET_ACTIVE_WINDOW = window id # 0x100000000\n",
            XorgMetadataFailureCode.MALFORMED_ACTIVE_WINDOW,
        ),
        ("_NET_ACTIVE_WINDOW = window id # 0x0\n", XorgMetadataFailureCode.NO_ACTIVE_WINDOW),
        (
            "_NET_ACTIVE_WINDOW: no such atom on any window.\n",
            XorgMetadataFailureCode.NO_ACTIVE_WINDOW,
        ),
        (
            "_NET_ACTIVE_WINDOW: not found.\n",
            XorgMetadataFailureCode.NO_ACTIVE_WINDOW,
        ),
    ],
)
def test_active_window_identifier_validation(payload: str, code: XorgMetadataFailureCode) -> None:
    reader = XpropXorgPropertyReader(runner=SyntheticCommandRunner([command_result(payload)]))

    if code is XorgMetadataFailureCode.NO_ACTIVE_WINDOW:
        assert asyncio.run(reader.active_window_id()) is None
    else:
        with pytest.raises(XorgAdapterFailure) as captured:
            asyncio.run(reader.active_window_id())
        assert captured.value.code is code


@pytest.mark.parametrize(
    "payload",
    [
        'WM_CLASS = "unterminated\n',
        "_NET_WM_DESKTOP = workspace-three\n",
        'WM_CLASS = "instance", "App"\nWM_CLASS = "duplicate", "App"\n',
        b"WM_CLASS = \xff\n",
    ],
)
def test_malformed_property_output_is_rejected(payload: str | bytes) -> None:
    raw = payload.encode() if isinstance(payload, str) else payload
    reader = XpropXorgPropertyReader(
        runner=SyntheticCommandRunner([XorgCommandResult(0, raw, b"")])
    )

    with pytest.raises(XorgAdapterFailure) as captured:
        asyncio.run(reader.window_properties(WINDOW_ID, include_title=True))

    assert captured.value.code is XorgMetadataFailureCode.MALFORMED_PROPERTY


def test_xwininfo_geometry_accepts_negative_monitor_coordinates() -> None:
    runner = SyntheticCommandRunner(
        [
            command_result('WM_CLASS = "instance", "App"\n_NET_WM_DESKTOP: not found.\n'),
            command_result(
                "xwininfo: Window id: 0x2a00007\n"
                "  Absolute upper-left X:  -1920\n"
                "  Absolute upper-left Y:  24\n"
                "  Width: 1280\n"
                "  Height: 720\n"
            ),
        ],
        available_commands=frozenset({XorgCommand.XPROP, XorgCommand.XWININFO}),
    )
    reader = XpropXorgPropertyReader(runner=runner)

    snapshot = asyncio.run(reader.window_properties(WINDOW_ID, include_title=False))

    assert (snapshot.x, snapshot.y, snapshot.width, snapshot.height) == (-1920, 24, 1280, 720)


def _write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o700)


def test_fixed_runner_rejects_oversized_output(tmp_path: Path) -> None:
    executable = tmp_path / "xprop"
    _write_executable(executable, "printf '%080d' 0")
    runner = FixedXorgCommandRunner(XorgExecutablePaths(xprop=executable))

    with pytest.raises(XorgAdapterFailure) as captured:
        asyncio.run(
            runner.run(
                XorgCommand.XPROP,
                ("-version",),
                timeout_seconds=1.0,
                max_output_bytes=32,
            )
        )

    assert captured.value.code is XorgMetadataFailureCode.OUTPUT_TOO_LARGE


def test_fixed_runner_timeout_is_finite_and_sanitized(tmp_path: Path) -> None:
    executable = tmp_path / "xprop"
    _write_executable(executable, "sleep 1")
    runner = FixedXorgCommandRunner(XorgExecutablePaths(xprop=executable))

    with pytest.raises(XorgAdapterFailure) as captured:
        asyncio.run(
            runner.run(
                XorgCommand.XPROP,
                ("-version",),
                timeout_seconds=0.01,
                max_output_bytes=32,
            )
        )

    assert captured.value.code is XorgMetadataFailureCode.TIMEOUT


def test_fixed_runner_reports_missing_executable_without_path_leak() -> None:
    missing = Path("/synthetic-private-path/xprop")
    runner = FixedXorgCommandRunner(XorgExecutablePaths(xprop=missing))

    assert runner.is_available(XorgCommand.XPROP) is False
    with pytest.raises(XorgAdapterFailure) as captured:
        asyncio.run(
            runner.run(
                XorgCommand.XPROP,
                ("-version",),
                timeout_seconds=1.0,
                max_output_bytes=32,
            )
        )

    assert captured.value.code is XorgMetadataFailureCode.EXECUTABLE_UNAVAILABLE
    assert str(missing) not in str(captured.value)
    assert str(missing) not in repr(XorgExecutablePaths(xprop=missing))


def test_executable_paths_require_fixed_binary_names(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="fixed executable"):
        XorgExecutablePaths(xprop=tmp_path / "arbitrary-command")

    path = tmp_path / "xprop"
    _write_executable(path, "exit 0")
    resolved = XorgExecutablePaths.discover(environ={"PATH": os.fspath(tmp_path)})
    assert resolved.xprop == path.resolve()
