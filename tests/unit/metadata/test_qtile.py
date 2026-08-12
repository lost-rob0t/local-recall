from __future__ import annotations

import asyncio
import json
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
    FixedQtileCommandRunner,
    QtileAdapterFailure,
    QtileCommand,
    QtileCommandReader,
    QtileCommandResult,
    QtileExecutablePath,
    QtileMetadataFailure,
    QtileMetadataFailureCode,
    QtileMetadataSource,
    QtileSnapshot,
)
from local_recall.ports.metadata import MetadataSource

NOW = datetime(2026, 8, 12, 2, 3, 4, tzinfo=UTC)
WINDOW_ID = 0x2A00007


def request(*requested_fields: str) -> MetadataRequest:
    return MetadataRequest(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=time.monotonic_ns() + 10_000_000_000,
        requested_fields=frozenset(requested_fields),
    )


def snapshot(**overrides: object) -> QtileSnapshot:
    values: dict[str, object] = {
        "window_id": WINDOW_ID,
        "confirmed_window_id": WINDOW_ID,
        "application": "synthetic-app",
        "title": "Synthetic title",
        "workspace": "synthetic-workspace",
        "confirmed_workspace": "synthetic-workspace",
        "layout": "synthetic-layout",
        "confirmed_layout": "synthetic-layout",
        "screen": 1,
        "confirmed_screen": 1,
    }
    values.update(overrides)
    return QtileSnapshot(**values)  # type: ignore[arg-type]


@dataclass
class SyntheticReader:
    snapshots: list[QtileSnapshot | QtileAdapterFailure]
    available: bool = True
    availability_calls: int = 0
    snapshot_calls: list[bool] = field(default_factory=lambda: list[bool]())

    async def is_available(self) -> bool:
        self.availability_calls += 1
        return self.available

    async def snapshot(self, *, include_title: bool) -> QtileSnapshot:
        self.snapshot_calls.append(include_title)
        item = self.snapshots.pop(0)
        if isinstance(item, QtileAdapterFailure):
            raise item
        return item


def collect(
    reader: SyntheticReader,
    *,
    titles: bool = False,
    max_attempts: int = 2,
    metadata_request: MetadataRequest | None = None,
):
    source = QtileMetadataSource(
        MetadataSettings(window_titles_enabled=titles),
        reader=reader,
        now=lambda: NOW,
        max_attempts=max_attempts,
    )
    return asyncio.run(source.collect(metadata_request or request()))


def test_collects_valid_snapshot_in_canonical_field_order() -> None:
    reader = SyntheticReader([snapshot()])

    metadata = collect(reader, titles=True)

    assert tuple(field.name for field in metadata.fields) == (
        "application",
        "layout",
        "screen",
        "window.id",
        "window.title",
        "workspace",
    )
    assert metadata.observed_at == NOW
    assert metadata.get("application") == "synthetic-app"
    assert metadata.get("layout") == "synthetic-layout"
    assert metadata.get("screen") == 1
    assert metadata.get("window.id") == WINDOW_ID
    assert metadata.get("window.title") == "Synthetic title"
    assert metadata.get("workspace") == "synthetic-workspace"
    assert reader.snapshot_calls == [True]


def test_source_id_and_metadata_source_conformance() -> None:
    source = QtileMetadataSource(reader=SyntheticReader([snapshot()]))

    assert source.source_id == "qtile"
    assert isinstance(source, MetadataSource)


def test_title_is_disabled_by_default() -> None:
    reader = SyntheticReader([snapshot()])

    metadata = collect(reader)

    assert metadata.get("window.title") is None
    assert reader.snapshot_calls == [False]


def test_unrequested_title_is_not_emitted_or_requested() -> None:
    reader = SyntheticReader([snapshot()])

    metadata = collect(
        reader,
        titles=True,
        metadata_request=request("application", "workspace"),
    )

    assert tuple(field.name for field in metadata.fields) == ("application", "workspace")
    assert reader.snapshot_calls == [False]


def test_missing_optional_fields_are_omitted() -> None:
    reader = SyntheticReader(
        [
            snapshot(
                application=None,
                title=None,
                layout=None,
                confirmed_layout=None,
                screen=None,
                confirmed_screen=None,
            )
        ]
    )

    metadata = collect(reader, titles=True)

    assert tuple(field.name for field in metadata.fields) == ("window.id", "workspace")


def test_every_field_has_stable_provenance_and_confidence() -> None:
    metadata = collect(SyntheticReader([snapshot()]), titles=True)

    expected_confidence = {
        "application": 0.95,
        "layout": 0.98,
        "screen": 0.98,
        "window.id": 1.0,
        "window.title": 0.95,
        "workspace": 0.98,
    }
    for context_field in metadata.fields:
        provenance = context_field.provenance
        assert len(provenance) == 1
        assert provenance[0].source_id == "qtile"
        assert provenance[0].observed_at == NOW
        assert provenance[0].adapter_revision == "qtile-cmd-info-v1"
        assert provenance[0].confidence.value == expected_confidence[context_field.name]


@pytest.mark.parametrize(
    "code",
    [
        QtileMetadataFailureCode.NO_FOCUSED_WINDOW,
        QtileMetadataFailureCode.EXECUTABLE_UNAVAILABLE,
        QtileMetadataFailureCode.TIMEOUT,
        QtileMetadataFailureCode.OUTPUT_TOO_LARGE,
        QtileMetadataFailureCode.MALFORMED_RESPONSE,
        QtileMetadataFailureCode.UNSUPPORTED_RESPONSE,
    ],
)
def test_nontransient_adapter_failures_are_sanitized(code: QtileMetadataFailureCode) -> None:
    reader = SyntheticReader([QtileAdapterFailure(code)])

    with pytest.raises(QtileMetadataFailure) as captured:
        collect(reader)

    assert captured.value.code is code


@pytest.mark.parametrize(
    "transient_code",
    [
        QtileMetadataFailureCode.RESTARTING,
        QtileMetadataFailureCode.IPC_FAILURE,
    ],
)
def test_transient_failure_once_retries_then_succeeds(
    transient_code: QtileMetadataFailureCode,
) -> None:
    reader = SyntheticReader([QtileAdapterFailure(transient_code), snapshot()])

    metadata = collect(reader)

    assert metadata.get("window.id") == WINDOW_ID
    assert reader.snapshot_calls == [False, False]


def test_repeated_transient_failure_exhausts_fixed_budget() -> None:
    reader = SyntheticReader(
        [
            QtileAdapterFailure(QtileMetadataFailureCode.RESTARTING),
            QtileAdapterFailure(QtileMetadataFailureCode.RESTARTING),
        ]
    )

    with pytest.raises(QtileMetadataFailure) as captured:
        collect(reader)

    assert captured.value.code is QtileMetadataFailureCode.RESTARTING


@pytest.mark.parametrize(
    "changed",
    [
        {"confirmed_window_id": WINDOW_ID + 1},
        {"confirmed_workspace": "second-workspace"},
        {"confirmed_layout": "second-layout"},
        {"confirmed_screen": 2},
    ],
)
def test_state_change_retries_without_returning_mixed_metadata(
    changed: dict[str, object],
) -> None:
    reader = SyntheticReader([snapshot(**changed), snapshot()])

    metadata = collect(reader)

    assert metadata.get("workspace") == "synthetic-workspace"
    assert metadata.get("layout") == "synthetic-layout"
    assert metadata.get("screen") == 1
    assert reader.snapshot_calls == [False, False]


def test_repeated_focus_change_fails_with_fixed_reason() -> None:
    reader = SyntheticReader(
        [
            snapshot(confirmed_window_id=WINDOW_ID + 1),
            snapshot(confirmed_window_id=WINDOW_ID + 2),
        ]
    )

    with pytest.raises(QtileMetadataFailure) as captured:
        collect(reader)

    assert captured.value.code is QtileMetadataFailureCode.FOCUS_CHANGED


def test_wrong_window_group_identity_fails_cleanly() -> None:
    reader = SyntheticReader([QtileAdapterFailure(QtileMetadataFailureCode.WRONG_WINDOW)])

    with pytest.raises(QtileMetadataFailure) as captured:
        collect(reader)

    assert captured.value.code is QtileMetadataFailureCode.WRONG_WINDOW


def test_unknown_reader_exception_is_sanitized() -> None:
    marker = "synthetic-sensitive-exception"

    class BrokenReader(SyntheticReader):
        async def snapshot(self, *, include_title: bool) -> QtileSnapshot:
            del include_title
            raise RuntimeError(marker)

    with pytest.raises(QtileMetadataFailure) as captured:
        collect(BrokenReader([]))

    assert captured.value.code is QtileMetadataFailureCode.IPC_FAILURE
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)


def test_source_deadline_is_enforced_before_collection() -> None:
    source = QtileMetadataSource(
        reader=SyntheticReader([snapshot()]),
        monotonic_ns=lambda: 10,
    )
    expired = MetadataRequest(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=10,
    )

    with pytest.raises(QtileMetadataFailure) as captured:
        asyncio.run(source.collect(expired))

    assert captured.value.code is QtileMetadataFailureCode.TIMEOUT


@dataclass
class SyntheticRunner:
    results: list[QtileCommandResult | QtileAdapterFailure]
    available: bool = True
    calls: list[QtileCommand] = field(default_factory=lambda: list[QtileCommand]())

    def executable_available(self) -> bool:
        return self.available

    async def run(
        self,
        command: QtileCommand,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> QtileCommandResult:
        del timeout_seconds, max_output_bytes
        self.calls.append(command)
        item = self.results.pop(0)
        if isinstance(item, QtileAdapterFailure):
            raise item
        return item


def result(value: object, return_code: int = 0) -> QtileCommandResult:
    return QtileCommandResult(return_code, json.dumps(value).encode(), b"")


def valid_reader_results() -> list[QtileCommandResult | QtileAdapterFailure]:
    window = {
        "id": WINDOW_ID,
        "group": "synthetic-workspace",
        "wm_class": ["synthetic-instance", "Synthetic-App"],
        "name": "Synthetic title",
    }
    group = {
        "name": "synthetic-workspace",
        "layout": "synthetic-layout",
        "screen": 1,
    }
    return [result(window), result(group), result(group), result(window)]


def test_command_reader_parses_fixed_read_only_snapshot() -> None:
    runner = SyntheticRunner(valid_reader_results())
    reader = QtileCommandReader(runner=runner)

    parsed = asyncio.run(reader.snapshot(include_title=True))

    assert parsed == snapshot()
    assert runner.calls == [
        QtileCommand.WINDOW_INFO,
        QtileCommand.GROUP_INFO,
        QtileCommand.GROUP_INFO,
        QtileCommand.WINDOW_INFO,
    ]


def test_command_reader_normalizes_application_class() -> None:
    outputs = valid_reader_results()
    outputs[0] = result(
        {
            "id": WINDOW_ID,
            "group": "synthetic-workspace",
            "wm_class": ["Synthetic Instance", "  Synthetic APP  "],
            "name": "Synthetic title",
        }
    )
    outputs[-1] = outputs[0]

    parsed = asyncio.run(
        QtileCommandReader(runner=SyntheticRunner(outputs)).snapshot(include_title=False)
    )

    assert parsed.application == "synthetic app"
    assert parsed.title is None


def test_command_reader_omits_title_value_when_not_requested() -> None:
    parsed = asyncio.run(
        QtileCommandReader(runner=SyntheticRunner(valid_reader_results())).snapshot(
            include_title=False
        )
    )

    assert parsed.title is None
    assert "Synthetic title" not in repr(parsed)


def test_command_reader_tolerates_missing_optional_layout_and_screen() -> None:
    outputs = valid_reader_results()
    group = result({"name": "synthetic-workspace", "layout": None, "screen": None})
    outputs[1] = group
    outputs[2] = group

    parsed = asyncio.run(
        QtileCommandReader(runner=SyntheticRunner(outputs)).snapshot(include_title=False)
    )

    assert parsed.layout is None
    assert parsed.screen is None


@pytest.mark.parametrize(
    "bad_id",
    [0, -1, 0x100000000, True, "0x2a00007"],
)
def test_command_reader_rejects_malformed_window_identifier(bad_id: object) -> None:
    outputs = valid_reader_results()
    outputs[0] = result(
        {
            "id": bad_id,
            "group": "synthetic-workspace",
            "wm_class": ["instance", "app"],
            "name": "title",
        }
    )

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(
            QtileCommandReader(runner=SyntheticRunner(outputs)).snapshot(include_title=True)
        )

    assert captured.value.code is QtileMetadataFailureCode.MALFORMED_IDENTIFIER


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"[]",
        b'{"id": 1, "id": 2}',
        b'{"id": 1, "group": 3}',
        b'{"id": 1, "group": "workspace", "wm_class": "app"}',
        b'{"id": 1, "group": "workspace", "wm_class": ["app"], "name": 4}',
    ],
)
def test_command_reader_rejects_malformed_schema(payload: bytes) -> None:
    outputs = valid_reader_results()
    outputs[0] = QtileCommandResult(0, payload, b"")

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(
            QtileCommandReader(runner=SyntheticRunner(outputs)).snapshot(include_title=True)
        )

    assert captured.value.code in {
        QtileMetadataFailureCode.MALFORMED_IDENTIFIER,
        QtileMetadataFailureCode.MALFORMED_RESPONSE,
    }


def test_command_reader_rejects_wrong_window_group_identity() -> None:
    outputs = valid_reader_results()
    outputs[1] = result({"name": "different-workspace", "layout": "layout", "screen": 1})

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(
            QtileCommandReader(runner=SyntheticRunner(outputs)).snapshot(include_title=False)
        )

    assert captured.value.code is QtileMetadataFailureCode.WRONG_WINDOW


def test_command_reader_rejects_unsupported_response_marker() -> None:
    outputs = valid_reader_results()
    outputs[0] = result({"response_version": 2, "id": WINDOW_ID})

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(
            QtileCommandReader(runner=SyntheticRunner(outputs)).snapshot(include_title=False)
        )

    assert captured.value.code is QtileMetadataFailureCode.UNSUPPORTED_RESPONSE


def test_content_free_health_uses_status_only() -> None:
    runner = SyntheticRunner([result("OK")])
    reader = QtileCommandReader(runner=runner)

    assert asyncio.run(reader.is_available()) is True
    assert runner.calls == [QtileCommand.STATUS]


def test_missing_focused_window_is_distinguished_from_restart() -> None:
    runner = SyntheticRunner([result("unavailable", return_code=1), result("OK")])

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(QtileCommandReader(runner=runner).snapshot(include_title=False))

    assert captured.value.code is QtileMetadataFailureCode.NO_FOCUSED_WINDOW
    assert runner.calls == [QtileCommand.WINDOW_INFO, QtileCommand.STATUS]


def test_qtile_restart_during_collection_is_distinguished() -> None:
    runner = SyntheticRunner(
        [result("unavailable", return_code=1), result("unavailable", return_code=1)]
    )

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(QtileCommandReader(runner=runner).snapshot(include_title=False))

    assert captured.value.code is QtileMetadataFailureCode.RESTARTING


@pytest.mark.parametrize(
    "status_result",
    [
        result("not-ok"),
        result("OK", return_code=1),
        QtileCommandResult(0, b"not-json", b"synthetic-sensitive-error"),
    ],
)
def test_health_rejects_nonoperational_status_without_content(
    status_result: QtileCommandResult,
) -> None:
    runner = SyntheticRunner([status_result])
    reader = QtileCommandReader(runner=runner)

    assert asyncio.run(reader.is_available()) is False
    assert runner.calls == [QtileCommand.STATUS]


def test_source_availability_is_sanitized() -> None:
    marker = "synthetic-sensitive-health"

    class BrokenHealthReader(SyntheticReader):
        async def is_available(self) -> bool:
            raise RuntimeError(marker)

    source = QtileMetadataSource(reader=BrokenHealthReader([]))

    assert asyncio.run(source.is_available()) is False
    assert marker not in repr(source)


def test_representations_omit_adapter_content() -> None:
    marker = "synthetic-sensitive-adapter-content"
    command_result = QtileCommandResult(1, marker.encode(), marker.encode())
    state = snapshot(
        application=marker,
        title=marker,
        workspace=marker,
        confirmed_workspace=marker,
        layout=marker,
        confirmed_layout=marker,
    )

    assert marker not in repr(command_result)
    assert marker not in repr(state)


def _write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o700)


def test_fixed_runner_uses_only_reviewed_argument_vectors(tmp_path: Path) -> None:
    executable = tmp_path / "qtile"
    _write_executable(
        executable,
        "set -eu\n"
        'test "$#" -eq 5\n'
        'test "$1" = "cmd-obj"\n'
        'test "$2" = "-o"\n'
        'test "$3" = "cmd"\n'
        'test "$4" = "-f"\n'
        'test "$5" = "status"\n'
        "printf '\"OK\"'",
    )
    runner = FixedQtileCommandRunner(QtileExecutablePath(executable))

    command_result = asyncio.run(
        runner.run(
            QtileCommand.STATUS,
            timeout_seconds=1.0,
            max_output_bytes=32,
        )
    )

    assert command_result.stdout == b'"OK"'


def test_fixed_runner_rejects_oversized_output(tmp_path: Path) -> None:
    executable = tmp_path / "qtile"
    _write_executable(executable, "printf '%080d' 0")
    runner = FixedQtileCommandRunner(QtileExecutablePath(executable))

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(
            runner.run(
                QtileCommand.STATUS,
                timeout_seconds=1.0,
                max_output_bytes=32,
            )
        )

    assert captured.value.code is QtileMetadataFailureCode.OUTPUT_TOO_LARGE


def test_fixed_runner_timeout_is_finite_and_sanitized(tmp_path: Path) -> None:
    executable = tmp_path / "qtile"
    _write_executable(executable, "sleep 1")
    runner = FixedQtileCommandRunner(QtileExecutablePath(executable))

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(
            runner.run(
                QtileCommand.STATUS,
                timeout_seconds=0.01,
                max_output_bytes=32,
            )
        )

    assert captured.value.code is QtileMetadataFailureCode.TIMEOUT


def test_missing_executable_is_sanitized() -> None:
    missing = Path("/synthetic-private-path/qtile")
    runner = FixedQtileCommandRunner(QtileExecutablePath(missing))

    assert runner.executable_available() is False
    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(
            runner.run(
                QtileCommand.STATUS,
                timeout_seconds=1.0,
                max_output_bytes=32,
            )
        )

    assert captured.value.code is QtileMetadataFailureCode.EXECUTABLE_UNAVAILABLE
    assert str(missing) not in str(captured.value)
    assert str(missing) not in repr(QtileExecutablePath(missing))


def test_executable_path_requires_fixed_binary_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="fixed executable"):
        QtileExecutablePath(tmp_path / "arbitrary-command")

    path = tmp_path / "qtile"
    _write_executable(path, "exit 0")
    discovered = QtileExecutablePath.discover(environ={"PATH": os.fspath(tmp_path)})
    assert discovered.path == path.resolve()


def test_nonzero_command_result_is_ipc_failure() -> None:
    outputs = valid_reader_results()
    runner = SyntheticRunner(
        [outputs[0], result("synthetic-sensitive-error", return_code=1), result("OK")]
    )

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(QtileCommandReader(runner=runner).snapshot(include_title=False))

    assert captured.value.code is QtileMetadataFailureCode.IPC_FAILURE
    assert "synthetic-sensitive-error" not in str(captured.value)


def test_runner_failure_code_is_preserved_without_output() -> None:
    failure = QtileAdapterFailure(QtileMetadataFailureCode.OUTPUT_TOO_LARGE)
    runner = SyntheticRunner([failure])

    with pytest.raises(QtileAdapterFailure) as captured:
        asyncio.run(QtileCommandReader(runner=runner).snapshot(include_title=False))

    assert captured.value.code is QtileMetadataFailureCode.OUTPUT_TOO_LARGE
