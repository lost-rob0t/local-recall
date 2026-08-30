"""Wayland portal capture backend behind the shared capture strategy interface."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from time import monotonic_ns as system_monotonic_ns
from uuid import uuid4

from local_recall.capture.png import PngDecodeError, decode_png_rgb8
from local_recall.capture.portal import (
    MAX_PORTAL_SCREENSHOT_BYTES,
    PortalCaptureStatus,
    PortalError,
    PortalGateway,
    PortalPermissionState,
    PortalScreenshot,
)
from local_recall.domain.capture import ApprovedCaptureRequest
from local_recall.domain.frames import (
    CaptureProvenance,
    CaptureRegion,
    PixelFormat,
    RawFrame,
)

WAYLAND_PORTAL_BACKEND_ID = "wayland-portal"
WAYLAND_PORTAL_BACKEND_REVISION = "portal-screenshot-v1"
_AUTHORIZATION_MODEL = "per-capture-portal-request"
_LIMITATIONS = (
    "authorization-required-per-capture",
    "window-metadata-unavailable",
    "persistent-sessions-not-used",
    "screencast-streams-not-supported",
    "region-cropping-unavailable",
)


class WaylandPortalCaptureBackend:
    """Capture pixels only through explicit per-capture portal authorization."""

    __slots__ = (
        "_gateway",
        "_in_flight",
        "_max_screenshot_bytes",
        "_monotonic_ns",
        "_permission_state",
        "_revocations",
        "_successful_authorizations",
    )

    def __init__(
        self,
        *,
        gateway: PortalGateway,
        monotonic_ns: Callable[[], int] = system_monotonic_ns,
        max_screenshot_bytes: int = MAX_PORTAL_SCREENSHOT_BYTES,
    ) -> None:
        if max_screenshot_bytes <= 0 or max_screenshot_bytes > MAX_PORTAL_SCREENSHOT_BYTES:
            raise ValueError("portal screenshot byte bound is invalid")
        self._gateway = gateway
        self._monotonic_ns = monotonic_ns
        self._max_screenshot_bytes = max_screenshot_bytes
        self._permission_state = PortalPermissionState.UNAUTHORIZED
        self._in_flight: set[asyncio.Future[None]] = set()
        self._successful_authorizations = 0
        self._revocations = 0

    @property
    def backend_id(self) -> str:
        return WAYLAND_PORTAL_BACKEND_ID

    @property
    def permission_state(self) -> PortalPermissionState:
        return self._permission_state

    def validate_request(self, request: object) -> None:
        if not isinstance(request, ApprovedCaptureRequest):
            raise TypeError("approved capture request required")

    async def capture(self, request: ApprovedCaptureRequest) -> RawFrame:
        self.validate_request(request)
        if self._permission_state is PortalPermissionState.REVOKED:
            raise PortalError("portal-permission-revoked")
        deadline = request.intent.deadline_monotonic_ns
        if self._monotonic_ns() >= deadline:
            raise PortalError("portal-deadline-expired")

        loop = asyncio.get_running_loop()
        revocation: asyncio.Future[None] = loop.create_future()
        self._in_flight.add(revocation)
        try:
            gateway_task = asyncio.ensure_future(
                self._gateway.request_screenshot(deadline_monotonic_ns=deadline)
            )
            remaining_seconds = (deadline - self._monotonic_ns()) / 1_000_000_000
            done, _pending = await asyncio.wait(
                (gateway_task, revocation),
                timeout=remaining_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if revocation in done:
                gateway_task.cancel()
                await asyncio.gather(gateway_task, return_exceptions=True)
                raise PortalError("portal-permission-revoked") from None
            if gateway_task not in done:
                gateway_task.cancel()
                await asyncio.gather(gateway_task, return_exceptions=True)
                raise PortalError("portal-deadline-expired") from None
            try:
                screenshot = gateway_task.result()
            except PortalError:
                raise
            except Exception:
                raise PortalError("portal-request-failed") from None
            if self._monotonic_ns() >= deadline:
                raise PortalError("portal-deadline-expired")
            frame = self._build_frame(request, screenshot)
            self._permission_state = PortalPermissionState.AUTHORIZED
            self._successful_authorizations += 1
            return frame
        finally:
            self._in_flight.discard(revocation)

    def revoke(self) -> None:
        """Revoke portal permission now and invalidate all queued capture work."""
        self._revocations += 1
        self._permission_state = PortalPermissionState.REVOKED
        for pending in tuple(self._in_flight):
            if not pending.done():
                pending.set_exception(PortalError("portal-permission-revoked"))
        self._in_flight.clear()

    def status(self) -> PortalCaptureStatus:
        return PortalCaptureStatus(
            backend_id=WAYLAND_PORTAL_BACKEND_ID,
            permission_state=self._permission_state,
            authorization_model=_AUTHORIZATION_MODEL,
            persistent_sessions=False,
            successful_authorizations=self._successful_authorizations,
            revocations=self._revocations,
            limitations=_LIMITATIONS,
        )

    def _build_frame(
        self, request: ApprovedCaptureRequest, screenshot: PortalScreenshot
    ) -> RawFrame:
        if screenshot.image_format != "png":
            raise PortalError("portal-screenshot-unavailable")
        if len(screenshot.payload) > self._max_screenshot_bytes:
            raise PortalError("portal-response-oversized")
        try:
            image = decode_png_rgb8(screenshot.payload)
        except PngDecodeError:
            raise PortalError("portal-screenshot-unavailable") from None
        region = CaptureRegion(0, 0, image.width, image.height)
        return RawFrame(
            frame_id=uuid4(),
            generation=request.intent.generation,
            captured_at=screenshot.captured_at,
            width=image.width,
            height=image.height,
            stride=image.stride,
            pixel_format=PixelFormat.RGB8,
            pixels=image.pixels,
            metadata=request.metadata,
            capture_provenance=CaptureProvenance(
                backend_id=WAYLAND_PORTAL_BACKEND_ID,
                backend_revision=WAYLAND_PORTAL_BACKEND_REVISION,
                root_region=region,
                region=region,
                monitors=(),
            ),
        )
