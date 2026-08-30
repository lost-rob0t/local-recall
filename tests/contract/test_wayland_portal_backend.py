from __future__ import annotations

from datetime import UTC, datetime

from local_recall.capture.png import encode_png_rgb8
from local_recall.capture.portal import PortalScreenshot
from local_recall.capture.wayland import WaylandPortalCaptureBackend
from local_recall.domain.capture import ApprovedCaptureRequest
from local_recall.ports.capture import CaptureBackend

from .suites import CaptureBackendContract
from .test_reusable_suites import approved_request

_NOW = datetime(2026, 8, 30, tzinfo=UTC)


class FakeContractPortalGateway:
    async def request_screenshot(self, *, deadline_monotonic_ns: int) -> PortalScreenshot:
        del deadline_monotonic_ns
        return PortalScreenshot(
            captured_at=_NOW,
            image_format="png",
            payload=encode_png_rgb8(width=1, height=1, stride=3, pixels=b"\x10\x20\x30"),
        )


class TestWaylandPortalCaptureBackend(CaptureBackendContract):
    def make_capture_backend(self) -> CaptureBackend:
        return WaylandPortalCaptureBackend(
            gateway=FakeContractPortalGateway(),
            monotonic_ns=lambda: 0,
        )

    def make_approved_request(self) -> ApprovedCaptureRequest:
        return approved_request()
