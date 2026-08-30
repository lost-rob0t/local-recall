from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall import domain
from local_recall.capture.png import encode_png_rgb8
from local_recall.capture.portal import (
    MAX_PORTAL_SCREENSHOT_BYTES,
    PortalCaptureStatus,
    PortalError,
    PortalPermissionState,
    PortalScreenshot,
)
from local_recall.capture.wayland import (
    WAYLAND_PORTAL_BACKEND_ID,
    WAYLAND_PORTAL_BACKEND_REVISION,
    WaylandPortalCaptureBackend,
)
from local_recall.domain.frames import PixelFormat
from local_recall.ports.capture import CaptureBackend

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


@dataclass
class FakePortalGateway:
    """Scripted portal gateway with optional blocking for revocation races."""

    screenshots: list[PortalScreenshot] = field(default_factory=list[PortalScreenshot])
    error: PortalError | None = None
    unexpected_error: Exception | None = None
    gate: asyncio.Event | None = None
    requests: int = 0

    async def request_screenshot(self, *, deadline_monotonic_ns: int) -> PortalScreenshot:
        self.requests += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.error is not None:
            raise self.error
        if self.unexpected_error is not None:
            raise self.unexpected_error
        return self.screenshots.pop(0)


def _screenshot(width: int = 2, height: int = 2) -> PortalScreenshot:
    stride = width * 3
    pixels = bytes(range(stride * height))
    return PortalScreenshot(
        captured_at=NOW,
        image_format="png",
        payload=encode_png_rgb8(width=width, height=height, stride=stride, pixels=pixels),
    )


def _request(deadline: int = 9_000_000_000) -> domain.ApprovedCaptureRequest:
    intent = domain.CaptureIntent(
        job_id=uuid4(),
        generation=domain.CaptureGeneration(7),
        requested_at=NOW,
        deadline_monotonic_ns=deadline,
        configuration_revision="config-v1",
    )
    decision = domain.CaptureDecision.allow(
        policy_revision="policy-v4",
        allowed_metadata_fields=frozenset({"window.x", "window.width"}),
    )
    return domain.ApprovedCaptureRequest.from_decision(
        intent=intent,
        metadata=domain.ContextMetadata(observed_at=NOW, fields=()),
        decision=decision,
    )


def _backend(
    gateway: FakePortalGateway,
    *,
    monotonic: int = 1_000_000_000,
    max_screenshot_bytes: int = MAX_PORTAL_SCREENSHOT_BYTES,
) -> WaylandPortalCaptureBackend:
    return WaylandPortalCaptureBackend(
        gateway=gateway,
        monotonic_ns=lambda: monotonic,
        max_screenshot_bytes=max_screenshot_bytes,
    )


def test_backend_satisfies_capture_strategy_interface() -> None:
    backend = _backend(FakePortalGateway())
    assert isinstance(backend, CaptureBackend)
    assert backend.backend_id == WAYLAND_PORTAL_BACKEND_ID
    assert WAYLAND_PORTAL_BACKEND_REVISION == "portal-screenshot-v1"


def test_backend_rejects_non_approved_request() -> None:
    backend = _backend(FakePortalGateway())
    with pytest.raises(TypeError):
        backend.validate_request(object())


def test_capture_returns_rgb8_frame_from_png_screenshot() -> None:
    gateway = FakePortalGateway(screenshots=[_screenshot(3, 2)])
    backend = _backend(gateway)
    request = _request()

    frame = asyncio.run(backend.capture(request))

    assert frame.width == 3
    assert frame.height == 2
    assert frame.stride == 9
    assert frame.pixel_format is PixelFormat.RGB8
    assert frame.generation is request.intent.generation
    assert frame.metadata is request.metadata
    assert frame.captured_at == NOW
    assert frame.pixels == bytes(range(9 * 2))
    provenance = frame.capture_provenance
    assert provenance is not None
    assert provenance.backend_id == "wayland-portal"
    assert provenance.backend_revision == "portal-screenshot-v1"
    assert provenance.region.width == 3
    assert provenance.region.height == 2
    assert provenance.monitors == ()


def test_capture_initializes_permission_state_to_authorized() -> None:
    gateway = FakePortalGateway(screenshots=[_screenshot()])
    backend = _backend(gateway)
    assert backend.permission_state is PortalPermissionState.UNAUTHORIZED
    asyncio.run(backend.capture(_request()))
    assert backend.permission_state is PortalPermissionState.AUTHORIZED


def test_portal_permission_denial_surfaces_sanitized_reason() -> None:
    gateway = FakePortalGateway(error=PortalError("portal-permission-denied"))
    backend = _backend(gateway)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert raised.value.reason_code == "portal-permission-denied"
    assert backend.permission_state is PortalPermissionState.UNAUTHORIZED


def test_portal_unavailability_is_content_free() -> None:
    gateway = FakePortalGateway(error=PortalError("portal-unavailable"))
    backend = _backend(gateway)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert str(raised.value) == "portal-unavailable"
    assert raised.value.reason_code == "portal-unavailable"


def test_unexpected_gateway_failure_is_sanitized() -> None:
    marker = "synthetic-sensitive-gateway-marker"
    gateway = FakePortalGateway(unexpected_error=RuntimeError(marker))
    backend = _backend(gateway)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert raised.value.reason_code == "portal-request-failed"
    assert str(raised.value) == "portal-request-failed"
    assert marker not in repr(raised.value)


def test_expired_deadline_prevents_portal_request() -> None:
    gateway = FakePortalGateway(screenshots=[_screenshot()])
    backend = _backend(gateway, monotonic=20_000_000_000)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request(deadline=9_000_000_000)))

    assert raised.value.reason_code == "portal-deadline-expired"
    assert gateway.requests == 0


def test_deadline_during_portal_request_is_enforced() -> None:
    gateway = FakePortalGateway(screenshots=[_screenshot()], gate=asyncio.Event())
    backend = _backend(gateway, monotonic=1_000_000_000)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request(deadline=1_050_000_000)))

    assert raised.value.reason_code == "portal-deadline-expired"
    assert gateway.requests == 1


def test_oversized_screenshot_payload_is_rejected() -> None:
    gateway = FakePortalGateway(screenshots=[_screenshot()])
    backend = _backend(gateway, max_screenshot_bytes=4)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert raised.value.reason_code == "portal-response-oversized"
    assert backend.permission_state is PortalPermissionState.UNAUTHORIZED


def test_invalid_png_payload_is_sanitized() -> None:
    gateway = FakePortalGateway(
        screenshots=[PortalScreenshot(captured_at=NOW, image_format="png", payload=b"not-a-png")]
    )
    backend = _backend(gateway)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert raised.value.reason_code == "portal-screenshot-unavailable"


def test_unknown_image_format_is_rejected() -> None:
    gateway = FakePortalGateway(
        screenshots=[PortalScreenshot(captured_at=NOW, image_format="jpeg", payload=b"junk")]
    )
    backend = _backend(gateway)

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert raised.value.reason_code == "portal-screenshot-unavailable"


def test_revoke_invalidates_in_flight_capture() -> None:
    gate = asyncio.Event()
    gateway = FakePortalGateway(screenshots=[_screenshot()], gate=gate)
    backend = _backend(gateway)

    async def scenario() -> None:
        task = asyncio.ensure_future(backend.capture(_request()))
        await asyncio.sleep(0.01)
        assert gateway.requests == 1
        backend.revoke()
        with pytest.raises(PortalError) as raised:
            await task
        assert raised.value.reason_code == "portal-permission-revoked"

    asyncio.run(scenario())
    assert backend.permission_state is PortalPermissionState.REVOKED


def test_revoke_blocks_subsequent_capture_without_portal_request() -> None:
    gateway = FakePortalGateway(screenshots=[_screenshot()])
    backend = _backend(gateway)
    backend.revoke()

    with pytest.raises(PortalError) as raised:
        asyncio.run(backend.capture(_request()))

    assert raised.value.reason_code == "portal-permission-revoked"
    assert gateway.requests == 0


def test_late_gateway_success_after_revoke_is_discarded() -> None:
    gate = asyncio.Event()
    gateway = FakePortalGateway(screenshots=[_screenshot()], gate=gate)
    backend = _backend(gateway)

    async def scenario() -> None:
        task = asyncio.ensure_future(backend.capture(_request()))
        await asyncio.sleep(0)
        backend.revoke()
        with pytest.raises(PortalError):
            await task
        gate.set()

    asyncio.run(scenario())
    assert len(gateway.screenshots) == 1


def test_concurrent_captures_are_all_invalidated_by_revoke() -> None:
    gate = asyncio.Event()
    gateway = FakePortalGateway(screenshots=[_screenshot() for _ in range(5)], gate=gate)
    backend = _backend(gateway)

    async def scenario() -> None:
        tasks = [asyncio.ensure_future(backend.capture(_request())) for _ in range(5)]
        await asyncio.sleep(0.01)
        assert gateway.requests == 5
        backend.revoke()
        for task in tasks:
            with pytest.raises(PortalError) as raised:
                await task
            assert raised.value.reason_code == "portal-permission-revoked"

    asyncio.run(scenario())


def test_repeated_revoke_is_idempotent() -> None:
    backend = _backend(FakePortalGateway())
    backend.revoke()
    backend.revoke()
    assert backend.permission_state is PortalPermissionState.REVOKED


def test_status_snapshot_is_content_free_and_accurate() -> None:
    gateway = FakePortalGateway(screenshots=[_screenshot(), _screenshot()])
    backend = _backend(gateway)
    marker = "synthetic-pixel-secret"
    assert marker not in repr(backend.status())

    asyncio.run(backend.capture(_request()))
    first = backend.status()
    assert isinstance(first, PortalCaptureStatus)
    assert first.backend_id == "wayland-portal"
    assert first.permission_state is PortalPermissionState.AUTHORIZED
    assert first.authorization_model == "per-capture-portal-request"
    assert first.persistent_sessions is False
    assert first.successful_authorizations == 1
    assert first.revocations == 0
    assert first.limitations

    backend.revoke()
    second = backend.status()
    assert second.permission_state is PortalPermissionState.REVOKED
    assert second.revocations == 1
    assert second.successful_authorizations == 1
    assert second.limitations
