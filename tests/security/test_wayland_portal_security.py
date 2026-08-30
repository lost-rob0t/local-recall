from __future__ import annotations

import asyncio
import json
import os
import stat
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall import domain
from local_recall.capture.bus_portal import BusctlPortalGateway, PortalCommandResult
from local_recall.capture.png import encode_png_rgb8
from local_recall.capture.portal import PortalError, PortalScreenshot
from local_recall.capture.wayland import WaylandPortalCaptureBackend
from local_recall.session import (
    EnvironmentSnapshot,
    MetadataCapability,
    MetadataProbeResult,
    ProbeOutcome,
    ProbeReasonCode,
    ResolutionReasonCode,
    SessionResolver,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
PIXEL_MARKER = "synthetic-pixel-secret"
GATEWAY_MARKER = "synthetic-gateway-secret"


def _marker_pixels(width: int, height: int) -> bytes:
    stride = width * 3
    pixels = bytearray(stride * height)
    encoded = PIXEL_MARKER.encode()
    pixels[: len(encoded)] = encoded
    return bytes(pixels)


def _screenshot(width: int = 4, height: int = 4) -> PortalScreenshot:
    stride = width * 3
    return PortalScreenshot(
        captured_at=NOW,
        image_format="png",
        payload=encode_png_rgb8(
            width=width, height=height, stride=stride, pixels=_marker_pixels(width, height)
        ),
    )


@dataclass
class RevocationSpyGateway:
    gate: asyncio.Event | None = None
    requests: int = 0
    screenshots: list[PortalScreenshot] = field(default_factory=lambda: [_screenshot()] * 64)

    async def request_screenshot(self, *, deadline_monotonic_ns: int) -> PortalScreenshot:
        del deadline_monotonic_ns
        self.requests += 1
        if self.gate is not None:
            await self.gate.wait()
        return self.screenshots.pop(0)


def _request(deadline: int = 9_000_000_000) -> domain.ApprovedCaptureRequest:
    intent = domain.CaptureIntent(
        job_id=uuid4(),
        generation=domain.CaptureGeneration(3),
        requested_at=NOW,
        deadline_monotonic_ns=deadline,
        configuration_revision="config-v1",
    )
    decision = domain.CaptureDecision.allow(
        policy_revision="policy-v4",
        allowed_metadata_fields=frozenset(),
    )
    return domain.ApprovedCaptureRequest.from_decision(
        intent=intent,
        metadata=domain.ContextMetadata(observed_at=NOW, fields=()),
        decision=decision,
    )


def _backend(
    gateway: RevocationSpyGateway, *, monotonic: int = 1_000_000_000
) -> WaylandPortalCaptureBackend:
    return WaylandPortalCaptureBackend(gateway=gateway, monotonic_ns=lambda: monotonic)


def test_portal_failures_never_leak_gateway_or_pixel_content() -> None:
    backend = _backend(RevocationSpyGateway())

    async def leak_gateway_error() -> str:
        class LeakingGateway:
            async def request_screenshot(self, *, deadline_monotonic_ns: int) -> PortalScreenshot:
                del deadline_monotonic_ns
                raise RuntimeError(f"{GATEWAY_MARKER} {PIXEL_MARKER}")

        failing = WaylandPortalCaptureBackend(gateway=LeakingGateway())
        try:
            await failing.capture(_request())
        except PortalError as error:
            return f"{error} {error!r}"
        raise AssertionError("gateway error was not converted")

    rendered = asyncio.run(leak_gateway_error())
    assert GATEWAY_MARKER not in rendered
    assert PIXEL_MARKER not in rendered

    status = repr(backend.status())
    assert GATEWAY_MARKER not in status
    assert PIXEL_MARKER not in status


def test_invalid_png_with_marker_payload_is_sanitized() -> None:
    gateway = RevocationSpyGateway()
    gateway.screenshots = [
        PortalScreenshot(captured_at=NOW, image_format="png", payload=PIXEL_MARKER.encode())
    ]
    backend = _backend(gateway)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert raised.value.reason_code == "portal-screenshot-unavailable"
    assert PIXEL_MARKER not in str(raised.value)
    assert PIXEL_MARKER not in repr(raised.value)


def test_revocation_stops_capture_under_concurrent_load() -> None:
    gateway = RevocationSpyGateway(gate=asyncio.Event())
    backend = _backend(gateway)

    async def scenario() -> None:
        tasks = [asyncio.ensure_future(backend.capture(_request())) for _ in range(50)]
        await asyncio.sleep(0.01)
        assert gateway.requests == 50
        backend.revoke()
        requests_at_revocation = gateway.requests
        for task in tasks:
            with pytest.raises(PortalError) as raised:
                await task
            assert raised.value.reason_code == "portal-permission-revoked"
        await asyncio.sleep(0.01)
        assert gateway.requests == requests_at_revocation

    asyncio.run(scenario())
    assert backend.status().permission_state.value == "revoked"


def test_wayland_resolver_never_falls_back_to_xorg_backend() -> None:
    class FailedPortalProbe:
        source_id = "wayland-portal"

        async def probe(self, session: object) -> MetadataProbeResult:
            del session
            return MetadataProbeResult(
                source_id="wayland-portal",
                outcome=ProbeOutcome.UNAVAILABLE,
                reason_code=ProbeReasonCode.UNAVAILABLE,
            )

    class HealthyXorgProbe:
        source_id = "xorg-generic"

        async def probe(self, session: object) -> MetadataProbeResult:
            del session
            return MetadataProbeResult(
                source_id="xorg-generic",
                outcome=ProbeOutcome.HEALTHY,
                reason_code=ProbeReasonCode.AVAILABLE,
                capabilities=frozenset(
                    {MetadataCapability.APPLICATION, MetadataCapability.WINDOW_TITLE}
                ),
            )

    resolver = SessionResolver(
        (),
        generic_xorg_probe=HealthyXorgProbe(),
        wayland_portal_probe=FailedPortalProbe(),
    )
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "wayland",
            "WAYLAND_DISPLAY": "wayland-1",
            "XDG_CURRENT_DESKTOP": "sway",
        }
    )

    resolution = asyncio.run(resolver.resolve(snapshot, ("xorg-generic",)))

    assert resolution.recording_supported is False
    assert resolution.capture_backend_id is None
    assert resolution.reason_code is ResolutionReasonCode.PORTAL_UNAVAILABLE


def test_frame_provenance_never_claims_xorg_backend() -> None:
    gateway = RevocationSpyGateway()
    backend = _backend(gateway)

    frame = asyncio.run(backend.capture(_request()))

    provenance = frame.capture_provenance
    assert provenance is not None
    assert provenance.backend_id == "wayland-portal"
    assert provenance.backend_id != "xorg"
    assert "xorg" not in provenance.backend_revision


def test_bus_gateway_rejects_foreign_owned_screenshot_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    screenshot_path = tmp_path / "portal-shot.png"
    screenshot_path.write_bytes(b"png")
    runner_call = PortalCommandResult(
        return_code=0,
        stdout=b'o  "/org/freedesktop/portal/desktop/request/1_42/token"\n',
        stderr=b"",
    )

    class FakeRunner:
        available = True

        async def run(
            self,
            args: tuple[str, ...],
            *,
            timeout_seconds: float,
            max_output_bytes: int,
        ) -> PortalCommandResult:
            del args, timeout_seconds, max_output_bytes
            return runner_call

        async def read_lines(
            self,
            args: tuple[str, ...],
            *,
            deadline_monotonic_ns: int,
            max_line_bytes: int,
            max_lines: int,
        ) -> AsyncIterator[bytes]:
            del args, deadline_monotonic_ns, max_line_bytes, max_lines
            line = (
                json_response(
                    {
                        "type": "signal",
                        "path": "/org/freedesktop/portal/desktop/request/1_42/token",
                        "interface": "org.freedesktop.portal.Request",
                        "member": "Response",
                        "payload": {
                            "type": "(ua{sv})",
                            "data": [
                                0,
                                {"uri": {"type": "s", "data": f"file://{screenshot_path}"}},
                            ],
                        },
                    }
                )
                + "\n"
            ).encode()
            yield line

    real_fstat = os.fstat

    def foreign_fstat(fd: int) -> os.stat_result:
        result = real_fstat(fd)
        return os.stat_result(
            (
                stat.S_IFREG | 0o600,
                result.st_ino,
                result.st_dev,
                1,
                result.st_uid + 4_000_000_000,
                result.st_gid,
                result.st_size,
                result.st_atime_ns,
                result.st_mtime_ns,
                result.st_ctime_ns,
            )
        )

    monkeypatch.setattr(os, "fstat", foreign_fstat)
    gateway = BusctlPortalGateway(
        runner=FakeRunner(),
        token_factory=lambda: "token",
        monotonic_ns=lambda: 1_000_000_000,
    )

    with pytest.raises(PortalError) as raised:
        asyncio.run(gateway.request_screenshot(deadline_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-response-invalid"
    assert screenshot_path.exists()


def json_response(payload: object) -> str:
    return json.dumps(payload)
