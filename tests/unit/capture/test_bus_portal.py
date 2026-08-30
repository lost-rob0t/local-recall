from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from local_recall.capture.bus_portal import (
    BusctlPortalGateway,
    PortalCommandResult,
)
from local_recall.capture.png import encode_png_rgb8
from local_recall.capture.portal import PortalError, PortalScreenshot

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_REQUEST_PATH = "/org/freedesktop/portal/desktop/request/1_42/fixed-token"
_CALL_ARGS = (
    "--user",
    "call",
    "org.freedesktop.portal.Desktop",
    "/org/freedesktop/portal/desktop",
    "org.freedesktop.portal.Screenshot",
    "Screenshot",
    "sa{sv}",
    "",
    "1",
    "handle_token",
    "s",
    "fixed-token",
)


def _response_line(code: int, results: dict[str, str]) -> bytes:
    message: dict[str, object] = {
        "type": "signal",
        "path": _REQUEST_PATH,
        "interface": "org.freedesktop.portal.Request",
        "member": "Response",
        "payload": {
            "type": "(ua{sv})",
            "data": [
                code,
                {name: {"type": "s", "data": value} for name, value in results.items()},
            ],
        },
    }
    return (json.dumps(message) + "\n").encode()


def _call_result() -> PortalCommandResult:
    return PortalCommandResult(
        return_code=0,
        stdout=f'o  "{_REQUEST_PATH}"\n'.encode(),
        stderr=b"",
    )


def _other_member_line() -> bytes:
    message: dict[str, object] = {
        "type": "signal",
        "path": _REQUEST_PATH,
        "interface": "org.freedesktop.portal.Request",
        "member": "Other",
        "payload": {"type": "(ua{sv})", "data": [0, {}]},
    }
    return (json.dumps(message) + "\n").encode()


@dataclass
class FakePortalRunner:
    call_result: PortalCommandResult = field(default_factory=_call_result)
    call_exception: Exception | None = None
    monitor_lines: tuple[bytes, ...] = ()
    monitor_never_completes: bool = False
    available: bool = True
    call_args: list[tuple[str, ...]] = field(default_factory=list[tuple[str, ...]])
    monitor_args: list[tuple[str, ...]] = field(default_factory=list[tuple[str, ...]])

    async def run(
        self,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> PortalCommandResult:
        del timeout_seconds, max_output_bytes
        self.call_args.append(args)
        if self.call_exception is not None:
            raise self.call_exception
        return self.call_result

    async def read_lines(
        self,
        args: tuple[str, ...],
        *,
        deadline_monotonic_ns: int,
        max_line_bytes: int,
        max_lines: int,
    ) -> AsyncIterator[bytes]:
        del deadline_monotonic_ns, max_line_bytes, max_lines
        self.monitor_args.append(args)
        for line in self.monitor_lines:
            yield line
        if self.monitor_never_completes:
            await asyncio.Event().wait()


def _gateway(
    runner: FakePortalRunner, *, max_screenshot_bytes: int = 512 * 1024 * 1024
) -> BusctlPortalGateway:
    return BusctlPortalGateway(
        runner=runner,
        token_factory=lambda: "fixed-token",
        now=lambda: NOW,
        monotonic_ns=lambda: 1_000_000_000,
        max_screenshot_bytes=max_screenshot_bytes,
    )


def test_gateway_satisfies_portal_gateway_protocol() -> None:
    from local_recall.capture.portal import PortalGateway

    assert isinstance(_gateway(FakePortalRunner()), PortalGateway)


def test_screenshot_request_uses_fixed_busctl_arguments() -> None:
    runner = FakePortalRunner(monitor_lines=(_response_line(0, {"uri": "file:///missing.png"}),))
    gateway = _gateway(runner)

    with pytest.raises(PortalError):
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert runner.call_args == [_CALL_ARGS]
    monitor_args = runner.monitor_args[0]
    assert monitor_args[:3] == ("--user", "monitor", "--json=short")
    match = monitor_args[4]
    assert "type='signal'" in match
    assert "interface='org.freedesktop.portal.Request'" in match
    assert "member='Response'" in match
    assert f"path='{_REQUEST_PATH}'" in match


def test_successful_flow_reads_png_and_unlinks_portal_file(tmp_path: Path) -> None:
    screenshot_path = tmp_path / "portal-shot.png"
    pixels = bytes(range(2 * 3 * 2))
    payload = encode_png_rgb8(width=2, height=2, stride=6, pixels=pixels)
    screenshot_path.write_bytes(payload)
    runner = FakePortalRunner(
        monitor_lines=(_response_line(0, {"uri": f"file://{screenshot_path}"}),)
    )

    screenshot = asyncio.run(
        _gateway(runner).request_screenshot(deadline_monotonic_ns=2_000_000_000)
    )

    assert isinstance(screenshot, PortalScreenshot)
    assert screenshot.image_format == "png"
    assert screenshot.payload == payload
    assert screenshot.captured_at == NOW
    assert not screenshot_path.exists()


def test_denied_response_maps_to_permission_denied(tmp_path: Path) -> None:
    screenshot_path = tmp_path / "portal-shot.png"
    screenshot_path.write_bytes(b"png")
    runner = FakePortalRunner(monitor_lines=(_response_line(1, {}),))
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-permission-denied"
    assert screenshot_path.exists()


def test_unexpected_response_code_maps_to_request_failed() -> None:
    runner = FakePortalRunner(monitor_lines=(_response_line(7, {}),))
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-request-failed"


def test_missing_uri_in_results_is_invalid() -> None:
    runner = FakePortalRunner(monitor_lines=(_response_line(0, {}),))
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-response-invalid"


def test_non_file_uri_is_invalid() -> None:
    runner = FakePortalRunner(
        monitor_lines=(_response_line(0, {"uri": "https://portal.invalid/shot.png"}),)
    )
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-response-invalid"


def test_path_traversal_uri_is_invalid(tmp_path: Path) -> None:
    uri = f"file://{tmp_path}/../escape.png"
    runner = FakePortalRunner(monitor_lines=(_response_line(0, {"uri": uri}),))
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-response-invalid"


def test_symlinked_uri_target_is_rejected_without_following(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"synthetic-secret-marker")
    link = tmp_path / "portal-shot.png"
    link.symlink_to(secret)
    runner = FakePortalRunner(monitor_lines=(_response_line(0, {"uri": f"file://{link}"}),))

    with pytest.raises(PortalError) as raised:
        asyncio.run(_gateway(runner).request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-response-invalid"
    assert secret.read_bytes() == b"synthetic-secret-marker"
    assert link.exists()


def test_directory_uri_is_invalid(tmp_path: Path) -> None:
    runner = FakePortalRunner(monitor_lines=(_response_line(0, {"uri": f"file://{tmp_path}"}),))
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-response-invalid"


def test_oversized_portal_file_is_rejected(tmp_path: Path) -> None:
    screenshot_path = tmp_path / "portal-shot.png"
    screenshot_path.write_bytes(b"X" * 64)
    runner = FakePortalRunner(
        monitor_lines=(_response_line(0, {"uri": f"file://{screenshot_path}"}),)
    )

    with pytest.raises(PortalError) as raised:
        asyncio.run(
            _gateway(runner, max_screenshot_bytes=8).request_screenshot(
                deadline_monotonic_ns=2_000_000_000
            )
        )

    assert raised.value.reason_code == "portal-response-oversized"


def test_call_failure_maps_to_screenshot_unavailable() -> None:
    stderr_marker = "Call failed: synthetic portal detail"
    runner = FakePortalRunner(
        call_result=PortalCommandResult(return_code=1, stdout=b"", stderr=stderr_marker.encode())
    )
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-screenshot-unavailable"
    assert str(raised.value) == "portal-screenshot-unavailable"
    assert "synthetic portal detail" not in repr(raised.value)


def test_unparsable_call_reply_is_invalid() -> None:
    runner = FakePortalRunner(
        call_result=PortalCommandResult(return_code=0, stdout=b"garbage reply", stderr=b"")
    )
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-response-invalid"


def test_busctl_unavailability_maps_to_portal_unavailable() -> None:
    runner = FakePortalRunner(available=False)
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-unavailable"


def test_spawn_failure_maps_to_portal_unavailable() -> None:
    runner = FakePortalRunner(call_exception=OSError("synthetic spawn failure"))
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-unavailable"


def test_monitor_stream_ending_without_response_is_unavailable() -> None:
    runner = FakePortalRunner(monitor_lines=())
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-unavailable"


def test_monitor_without_response_hits_deadline() -> None:
    runner = FakePortalRunner(monitor_never_completes=True)
    gateway = _gateway(runner)

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=1_030_000_000))

    assert raised.value.reason_code == "portal-deadline-expired"


def test_malformed_monitor_lines_are_skipped(tmp_path: Path) -> None:
    screenshot_path = tmp_path / "portal-shot.png"
    payload = encode_png_rgb8(width=1, height=1, stride=3, pixels=b"\x01\x02\x03")
    screenshot_path.write_bytes(payload)
    runner = FakePortalRunner(
        monitor_lines=(
            b"not-json\n",
            _other_member_line(),
            _response_line(0, {"uri": f"file://{screenshot_path}"}),
        )
    )

    screenshot = asyncio.run(
        _gateway(runner).request_screenshot(deadline_monotonic_ns=2_000_000_000)
    )

    assert screenshot.payload == payload


def test_uri_percent_encoding_is_decoded(tmp_path: Path) -> None:
    directory = tmp_path / "with space"
    directory.mkdir()
    screenshot_path = directory / "portal-shot.png"
    payload = encode_png_rgb8(width=1, height=1, stride=3, pixels=b"\x09\x08\x07")
    screenshot_path.write_bytes(payload)
    runner = FakePortalRunner(
        monitor_lines=(_response_line(0, {"uri": f"file://{directory}/portal-shot.png"}),)
    )

    screenshot = asyncio.run(
        _gateway(runner).request_screenshot(deadline_monotonic_ns=2_000_000_000)
    )

    assert screenshot.payload == payload


def test_gateway_reader_closes_file_descriptors(tmp_path: Path) -> None:
    screenshot_path = tmp_path / "portal-shot.png"
    payload = encode_png_rgb8(width=1, height=1, stride=3, pixels=b"\x04\x05\x06")
    screenshot_path.write_bytes(payload)
    before = count_open_files()
    runner = FakePortalRunner(
        monitor_lines=(_response_line(0, {"uri": f"file://{screenshot_path}"}),)
    )

    asyncio.run(_gateway(runner).request_screenshot(deadline_monotonic_ns=2_000_000_000))

    after = count_open_files()
    assert after <= before


def count_open_files() -> int:
    return len(os.listdir("/proc/self/fd"))
