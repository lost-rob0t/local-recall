from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import pytest

from local_recall import domain
from local_recall.capture import xorg as xorg_capture

NOW = datetime(2026, 8, 22, 6, 0, tzinfo=UTC)


@dataclass
class FakeReader:
    snapshot: xorg_capture.XorgSnapshot | None = None
    error: xorg_capture.XorgCaptureError | None = None
    calls: int = 0

    async def capture_root(self, *, deadline_monotonic_ns: int) -> xorg_capture.XorgSnapshot:
        assert deadline_monotonic_ns > 0
        self.calls += 1
        if self.error is not None:
            raise self.error
        assert self.snapshot is not None
        return self.snapshot


@dataclass
class FakeNativeRunner:
    dump: bytes
    layouts: list[tuple[xorg_capture.XorgMonitor, ...]]
    dump_calls: int = 0
    layout_calls: int = 0

    async def capture_root_dump(self, *, deadline_monotonic_ns: int) -> bytes:
        assert deadline_monotonic_ns > 0
        self.dump_calls += 1
        return self.dump

    async def monitor_layout(
        self, *, deadline_monotonic_ns: int
    ) -> tuple[xorg_capture.XorgMonitor, ...]:
        assert deadline_monotonic_ns > 0
        layout = self.layouts[min(self.layout_calls, len(self.layouts) - 1)]
        self.layout_calls += 1
        return layout


@dataclass
class FakeNativeExecutor:
    results: dict[str, xorg_capture.NativeCommandResult]
    calls: list[tuple[str, tuple[str, ...], int, int]] = field(default_factory=list)

    async def run(
        self,
        command: str,
        args: tuple[str, ...],
        *,
        deadline_monotonic_ns: int,
        max_output_bytes: int,
    ) -> xorg_capture.NativeCommandResult:
        self.calls.append((command, args, deadline_monotonic_ns, max_output_bytes))
        return self.results[command]


def _request(
    *, metadata: domain.ContextMetadata | None = None, deadline: int = 9_000_000_000
) -> domain.ApprovedCaptureRequest:
    intent = domain.CaptureIntent(
        job_id=uuid4(),
        generation=domain.CaptureGeneration(7),
        requested_at=NOW,
        deadline_monotonic_ns=deadline,
        configuration_revision="config-v1",
    )
    decision = domain.CaptureDecision.allow(
        policy_revision="policy-v4",
        allowed_metadata_fields=frozenset(
            {"window.x", "window.y", "window.width", "window.height"}
        ),
    )
    return domain.ApprovedCaptureRequest.from_decision(
        intent=intent,
        metadata=metadata or domain.ContextMetadata(observed_at=NOW, fields=()),
        decision=decision,
    )


def _snapshot() -> xorg_capture.XorgSnapshot:
    return xorg_capture.XorgSnapshot(
        captured_at=NOW,
        root_x=-2,
        root_y=0,
        width=4,
        height=2,
        stride=12,
        pixel_format=domain.PixelFormat.RGB8,
        pixels=bytes(range(24)),
        monitors=(
            xorg_capture.XorgMonitor(
                monitor_id="left",
                x=-2,
                y=0,
                width=2,
                height=2,
                scale_x=1.0,
                scale_y=1.0,
            ),
            xorg_capture.XorgMonitor(
                monitor_id="right",
                x=0,
                y=0,
                width=2,
                height=2,
                scale_x=1.5,
                scale_y=1.5,
            ),
        ),
        backend_revision="xlib-root-v1",
    )


def _window_metadata(*, source_id: str = "xorg-generic") -> domain.ContextMetadata:
    provenance = (
        domain.MetadataProvenance(
            source_id=source_id,
            observed_at=NOW,
            confidence=domain.SourceConfidence(0.99),
            adapter_revision="fixture-v1",
        ),
    )
    return domain.ContextMetadata(
        observed_at=NOW,
        fields=(
            domain.ContextField(name="window.x", value=0, provenance=provenance),
            domain.ContextField(name="window.y", value=0, provenance=provenance),
            domain.ContextField(name="window.width", value=2, provenance=provenance),
            domain.ContextField(name="window.height", value=2, provenance=provenance),
        ),
    )


def _xwd_truecolor_dump(*, width: int = 2, height: int = 1) -> bytes:
    name = b"root\0"
    header_size = 100 + len(name)
    bytes_per_line = width * 4
    header = struct.pack(
        ">25I",
        header_size,
        7,
        2,
        24,
        width,
        height,
        0,
        0,
        32,
        0,
        32,
        32,
        bytes_per_line,
        4,
        0x00FF0000,
        0x0000FF00,
        0x000000FF,
        8,
        256,
        0,
        width,
        height,
        0,
        0,
        0,
    )
    pixels = b"\x03\x02\x01\x00\x30\x20\x10\x00" * height
    return header + name + pixels[: bytes_per_line * height]


def _monitor_layout() -> tuple[xorg_capture.XorgMonitor, ...]:
    return (
        xorg_capture.XorgMonitor("left", 0, 0, 1, 1, 1.0, 1.0),
        xorg_capture.XorgMonitor("right", 1, 0, 1, 1, 1.25, 1.25),
    )


def test_full_desktop_capture_preserves_generation_and_monitor_provenance() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    frame = asyncio.run(backend.capture(_request()))

    assert backend.backend_id == "xorg"
    assert reader.calls == 1
    assert frame.generation == domain.CaptureGeneration(7)
    assert frame.width == 4
    assert frame.height == 2
    assert frame.pixels == bytes(range(24))
    assert frame.capture_provenance is not None
    assert frame.capture_provenance.backend_id == "xorg"
    assert frame.capture_provenance.backend_revision == "xlib-root-v1"
    assert [(m.x, m.width, m.scale_x) for m in frame.capture_provenance.monitors] == [
        (-2, 2, 1.0),
        (0, 2, 1.5),
    ]


def test_validated_window_geometry_crops_only_after_root_capture() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    frame = asyncio.run(backend.capture(_request(metadata=_window_metadata())))

    assert reader.calls == 1
    assert (frame.width, frame.height, frame.stride) == (2, 2, 6)
    assert frame.pixels == bytes([6, 7, 8, 9, 10, 11, 18, 19, 20, 21, 22, 23])
    assert frame.capture_provenance is not None
    assert frame.capture_provenance.region.x == 0
    assert frame.capture_provenance.region.width == 2


def test_untrusted_window_geometry_falls_back_to_full_desktop() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    frame = asyncio.run(
        backend.capture(_request(metadata=_window_metadata(source_id="unknown-source")))
    )

    assert (frame.width, frame.height) == (4, 2)
    assert frame.pixels == bytes(range(24))


def test_expired_deadline_fails_before_reader_is_invoked() -> None:
    reader = FakeReader(snapshot=_snapshot())
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 10_000_000_000)

    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-deadline-expired"):
        asyncio.run(backend.capture(_request(deadline=9_000_000_000)))

    assert reader.calls == 0


def test_reader_failure_is_sanitized() -> None:
    private_value = "DISPLAY=:77 private-display-value"
    reader = FakeReader(
        error=xorg_capture.XorgCaptureError("capture-failed", private_detail=private_value)
    )
    backend = xorg_capture.XorgCaptureBackend(reader=reader, monotonic_ns=lambda: 1_000_000_000)

    with pytest.raises(xorg_capture.XorgCaptureError) as caught:
        asyncio.run(backend.capture(_request()))

    rendered = f"{caught.value!r} {caught.value}"
    assert "capture-failed" in rendered
    assert private_value not in rendered


def test_capture_backend_rejects_unapproved_request_at_runtime() -> None:
    backend = xorg_capture.XorgCaptureBackend(
        reader=FakeReader(snapshot=_snapshot()), monotonic_ns=lambda: 1
    )
    intent = domain.CaptureIntent(
        job_id=uuid4(),
        generation=domain.CaptureGeneration(1),
        requested_at=NOW,
        deadline_monotonic_ns=2,
        configuration_revision="config-v1",
    )

    with pytest.raises(TypeError, match="approved capture request required"):
        backend.validate_request(cast(domain.ApprovedCaptureRequest, intent))


def test_native_xwd_reader_decodes_truecolor_into_memory() -> None:
    runner = FakeNativeRunner(dump=_xwd_truecolor_dump(), layouts=[_monitor_layout()])
    reader = xorg_capture.XwdSnapshotReader(runner=runner, now=lambda: NOW)

    snapshot = asyncio.run(reader.capture_root(deadline_monotonic_ns=9_000_000_000))

    assert (snapshot.width, snapshot.height, snapshot.stride) == (2, 1, 6)
    assert snapshot.pixel_format is domain.PixelFormat.RGB8
    assert snapshot.pixels == b"\x01\x02\x03\x10\x20\x30"
    assert snapshot.monitors == _monitor_layout()
    assert snapshot.backend_revision == "xwd-zpixmap-v1"
    assert runner.dump_calls == 1
    assert runner.layout_calls == 2


def test_native_xwd_reader_rejects_display_layout_change() -> None:
    first = _monitor_layout()
    second = (xorg_capture.XorgMonitor("solo", 0, 0, 2, 1),)
    runner = FakeNativeRunner(dump=_xwd_truecolor_dump(), layouts=[first, second])
    reader = xorg_capture.XwdSnapshotReader(runner=runner, now=lambda: NOW)

    with pytest.raises(xorg_capture.XorgCaptureError, match="display-changed"):
        asyncio.run(reader.capture_root(deadline_monotonic_ns=9_000_000_000))


def test_native_xwd_reader_rejects_malformed_or_oversized_dump() -> None:
    layout = _monitor_layout()
    malformed = FakeNativeRunner(dump=b"not-an-xwd", layouts=[layout])
    reader = xorg_capture.XwdSnapshotReader(runner=malformed, now=lambda: NOW)
    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-format-invalid"):
        asyncio.run(reader.capture_root(deadline_monotonic_ns=9_000_000_000))

    oversized_header = bytearray(_xwd_truecolor_dump())
    oversized_header[16:20] = (40_000).to_bytes(4, "big")
    oversized = FakeNativeRunner(dump=bytes(oversized_header), layouts=[layout])
    reader = xorg_capture.XwdSnapshotReader(runner=oversized, now=lambda: NOW)
    with pytest.raises(xorg_capture.XorgCaptureError, match="capture-format-invalid"):
        asyncio.run(reader.capture_root(deadline_monotonic_ns=9_000_000_000))


def test_fixed_native_runner_uses_only_xwd_root_stdout() -> None:
    dump = _xwd_truecolor_dump()
    executor = FakeNativeExecutor(
        results={"xwd": xorg_capture.NativeCommandResult(return_code=0, stdout=dump)}
    )
    runner = xorg_capture.FixedXwdNativeRunner(executor=executor)

    result = asyncio.run(runner.capture_root_dump(deadline_monotonic_ns=8_000_000_000))

    assert result == dump
    assert executor.calls == [
        ("xwd", ("-root", "-silent"), 8_000_000_000, xorg_capture.MAX_XWD_OUTPUT_BYTES)
    ]


def test_fixed_native_runner_parses_xrandr_monitor_geometry() -> None:
    output = (
        b"Monitors: 2\n"
        b" 0: +*DP-1 1920/344x1080/194+0+0  DP-1\n"
        b" 1: +HDMI-1 1280/509x720/286-1280+0 HDMI-1\n"
    )
    executor = FakeNativeExecutor(
        results={"xrandr": xorg_capture.NativeCommandResult(return_code=0, stdout=output)}
    )
    runner = xorg_capture.FixedXwdNativeRunner(executor=executor)

    monitors = asyncio.run(runner.monitor_layout(deadline_monotonic_ns=8_000_000_000))

    assert monitors == (
        xorg_capture.XorgMonitor("DP-1", 0, 0, 1920, 1080),
        xorg_capture.XorgMonitor("HDMI-1", -1280, 0, 1280, 720),
    )
    assert executor.calls == [
        (
            "xrandr",
            ("--listmonitors",),
            8_000_000_000,
            xorg_capture.MAX_MONITOR_OUTPUT_BYTES,
        )
    ]


def test_fixed_native_runner_sanitizes_command_failure_and_bad_layout() -> None:
    private_value = b"DISPLAY=:77 top-secret-display-error"
    failed = FakeNativeExecutor(
        results={
            "xwd": xorg_capture.NativeCommandResult(return_code=1, stdout=b"", stderr=private_value)
        }
    )
    runner = xorg_capture.FixedXwdNativeRunner(executor=failed)
    with pytest.raises(xorg_capture.XorgCaptureError, match="display-unavailable") as caught:
        asyncio.run(runner.capture_root_dump(deadline_monotonic_ns=8_000_000_000))
    assert private_value.decode() not in f"{caught.value!r} {caught.value}"

    malformed = FakeNativeExecutor(
        results={
            "xrandr": xorg_capture.NativeCommandResult(
                return_code=0, stdout=b"Monitors: 1\n hostile malformed payload\n"
            )
        }
    )
    runner = xorg_capture.FixedXwdNativeRunner(executor=malformed)
    with pytest.raises(xorg_capture.XorgCaptureError, match="monitor-layout-invalid"):
        asyncio.run(runner.monitor_layout(deadline_monotonic_ns=8_000_000_000))
