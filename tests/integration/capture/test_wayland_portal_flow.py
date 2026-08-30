from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

import pytest

from local_recall.capture.adaptive import (
    AdaptiveCaptureController,
    AdaptiveCaptureFlow,
    AdaptiveCaptureOutcome,
)
from local_recall.capture.png import encode_png_rgb8
from local_recall.capture.portal import (
    PortalCaptureStatus,
    PortalError,
    PortalPermissionState,
    PortalScreenshot,
)
from local_recall.capture.wayland import WaylandPortalCaptureBackend
from local_recall.domain.capture import ApprovedCaptureRequest, CaptureAuthorization, CaptureIntent
from local_recall.domain.frames import PixelFormat
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata

_NOW = datetime(2026, 8, 30, tzinfo=UTC)


def _metadata() -> ContextMetadata:
    return ContextMetadata(observed_at=_NOW, fields=())


def _request() -> ApprovedCaptureRequest:
    return ApprovedCaptureRequest(
        intent=CaptureIntent(
            job_id=UUID(int=1),
            generation=CaptureGeneration(1),
            requested_at=_NOW,
            deadline_monotonic_ns=10_000_000_000,
            configuration_revision="config-a",
        ),
        metadata=_metadata(),
        authorization=CaptureAuthorization(
            decision_id=UUID(int=2),
            policy_revision="policy-a",
            allowed_metadata_fields=frozenset(),
        ),
    )


@dataclass
class ScriptedPortalGateway:
    screenshots: list[PortalScreenshot] = field(default_factory=list[PortalScreenshot])
    requests: int = 0

    async def request_screenshot(self, *, deadline_monotonic_ns: int) -> PortalScreenshot:
        del deadline_monotonic_ns
        self.requests += 1
        return self.screenshots.pop(0)


def _screenshot(width: int = 9, height: int = 9, value: int = 20) -> PortalScreenshot:
    stride = width * 3
    pixels = bytes((value, value, value)) * (width * height)
    return PortalScreenshot(
        captured_at=_NOW,
        image_format="png",
        payload=encode_png_rgb8(width=width, height=height, stride=stride, pixels=pixels),
    )


def _flow(gateway: ScriptedPortalGateway) -> AdaptiveCaptureFlow:
    backend = WaylandPortalCaptureBackend(gateway=gateway, monotonic_ns=lambda: 1_000_000_000)
    controller = AdaptiveCaptureController(
        cadence_seconds=1.0, change_threshold=0.0, debounce_seconds=0.0
    )
    return AdaptiveCaptureFlow(backend=backend, controller=controller)


def test_portal_flow_admits_first_portal_frame() -> None:
    gateway = ScriptedPortalGateway(screenshots=[_screenshot()])
    flow = _flow(gateway)

    result = asyncio.run(flow.capture_if_due(request=_request(), now_monotonic_ns=1_000_000_000))

    assert result.outcome is AdaptiveCaptureOutcome.ADMIT
    assert result.frame is not None
    assert result.frame.pixel_format is PixelFormat.RGB8
    assert result.frame.capture_provenance is not None
    assert result.frame.capture_provenance.backend_id == "wayland-portal"


def test_portal_flow_reports_coalesce_for_identical_frames() -> None:
    gateway = ScriptedPortalGateway(screenshots=[_screenshot(), _screenshot(value=20)])
    flow = _flow(gateway)

    first = asyncio.run(flow.capture_if_due(request=_request(), now_monotonic_ns=1_000_000_000))
    second = asyncio.run(flow.capture_if_due(request=_request(), now_monotonic_ns=2_000_000_000))

    assert first.outcome is AdaptiveCaptureOutcome.ADMIT
    assert second.outcome is AdaptiveCaptureOutcome.COALESCE


def test_portal_flow_stops_after_revocation() -> None:
    gateway = ScriptedPortalGateway(screenshots=[_screenshot(), _screenshot(value=30)])
    backend = WaylandPortalCaptureBackend(gateway=gateway, monotonic_ns=lambda: 1_000_000_000)
    controller = AdaptiveCaptureController(
        cadence_seconds=1.0, change_threshold=1.0, debounce_seconds=0.0
    )
    flow = AdaptiveCaptureFlow(backend=backend, controller=controller)

    first = asyncio.run(flow.capture_if_due(request=_request(), now_monotonic_ns=1_000_000_000))
    assert first.outcome is AdaptiveCaptureOutcome.ADMIT

    backend.revoke()
    requests_before = gateway.requests

    with pytest.raises(PortalError) as raised:
        asyncio.run(flow.capture_if_due(request=_request(), now_monotonic_ns=2_000_000_000))

    assert raised.value.reason_code == "portal-permission-revoked"
    assert gateway.requests == requests_before
    status: PortalCaptureStatus = backend.status()
    assert status.permission_state is PortalPermissionState.REVOKED
    assert status.persistent_sessions is False
