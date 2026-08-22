"""Xorg desktop capture boundary."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from time import monotonic_ns as system_monotonic_ns
from typing import Protocol, runtime_checkable
from uuid import uuid4

from local_recall.domain.capture import ApprovedCaptureRequest
from local_recall.domain.frames import (
    CaptureProvenance,
    CaptureRegion,
    MonitorGeometry,
    PixelFormat,
    RawFrame,
)
from local_recall.domain.metadata import ContextField

_TRUSTED_GEOMETRY_SOURCES = frozenset({"xorg-generic", "qtile"})
_GEOMETRY_FIELDS = ("window.x", "window.y", "window.width", "window.height")
_MAX_DIMENSION = 32_768
_MAX_PIXEL_BYTES = 512 * 1024 * 1024


class XorgCaptureError(RuntimeError):
    """Content-free Xorg capture failure."""

    def __init__(self, reason_code: str, *, private_detail: object | None = None) -> None:
        del private_detail
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class XorgMonitor:
    monitor_id: str
    x: int
    y: int
    width: int
    height: int
    scale_x: float = 1.0
    scale_y: float = 1.0

    def to_domain(self) -> MonitorGeometry:
        return MonitorGeometry(
            monitor_id=self.monitor_id,
            x=self.x,
            y=self.y,
            width=self.width,
            height=self.height,
            scale_x=self.scale_x,
            scale_y=self.scale_y,
        )


@dataclass(frozen=True, slots=True)
class XorgSnapshot:
    captured_at: datetime
    root_x: int
    root_y: int
    width: int
    height: int
    stride: int
    pixel_format: PixelFormat
    pixels: bytes
    monitors: tuple[XorgMonitor, ...]
    backend_revision: str

    def __post_init__(self) -> None:
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("capture timestamp must be timezone-aware")
        if not 0 < self.width <= _MAX_DIMENSION or not 0 < self.height <= _MAX_DIMENSION:
            raise ValueError("capture dimensions are out of bounds")
        minimum_stride = self.width * self.pixel_format.bytes_per_pixel
        if self.stride < minimum_stride:
            raise ValueError("capture stride is smaller than pixel width")
        required_size = self.stride * self.height
        if required_size > _MAX_PIXEL_BYTES or len(self.pixels) != required_size:
            raise ValueError("capture pixel buffer is invalid")
        if not self.backend_revision:
            raise ValueError("capture backend revision must not be empty")
        for monitor in self.monitors:
            monitor.to_domain()


@runtime_checkable
class XorgSnapshotReader(Protocol):
    async def capture_root(self, *, deadline_monotonic_ns: int) -> XorgSnapshot: ...


class XorgCaptureBackend:
    """Capture pixels only after existing policy/lifecycle authorization."""

    def __init__(
        self,
        *,
        reader: XorgSnapshotReader,
        monotonic_ns: Callable[[], int] = system_monotonic_ns,
    ) -> None:
        self._reader = reader
        self._monotonic_ns = monotonic_ns

    @property
    def backend_id(self) -> str:
        return "xorg"

    def validate_request(self, request: object) -> None:
        if not isinstance(request, ApprovedCaptureRequest):
            raise TypeError("approved capture request required")

    async def capture(self, request: ApprovedCaptureRequest) -> RawFrame:
        self.validate_request(request)
        deadline = request.intent.deadline_monotonic_ns
        if self._monotonic_ns() >= deadline:
            raise XorgCaptureError("capture-deadline-expired")

        try:
            snapshot = await self._reader.capture_root(deadline_monotonic_ns=deadline)
        except XorgCaptureError:
            raise
        except Exception as error:
            raise XorgCaptureError("capture-failed", private_detail=error) from None

        if self._monotonic_ns() >= deadline:
            raise XorgCaptureError("capture-deadline-expired")

        region = _trusted_window_region(request, snapshot)
        if region is None:
            region = CaptureRegion(
                snapshot.root_x, snapshot.root_y, snapshot.width, snapshot.height
            )
            pixels = snapshot.pixels
            stride = snapshot.stride
        else:
            pixels, stride = _crop_snapshot(snapshot, region)

        provenance = CaptureProvenance(
            backend_id=self.backend_id,
            backend_revision=snapshot.backend_revision,
            root_region=CaptureRegion(
                snapshot.root_x, snapshot.root_y, snapshot.width, snapshot.height
            ),
            region=region,
            monitors=tuple(monitor.to_domain() for monitor in snapshot.monitors),
        )
        return RawFrame(
            frame_id=uuid4(),
            generation=request.intent.generation,
            captured_at=snapshot.captured_at,
            width=region.width,
            height=region.height,
            stride=stride,
            pixel_format=snapshot.pixel_format,
            pixels=pixels,
            metadata=request.metadata,
            capture_provenance=provenance,
        )


def _trusted_window_region(
    request: ApprovedCaptureRequest, snapshot: XorgSnapshot
) -> CaptureRegion | None:
    if not set(_GEOMETRY_FIELDS).issubset(request.authorization.allowed_metadata_fields):
        return None
    fields = {field.name: field for field in request.metadata.fields}
    x = _trusted_geometry_value(fields.get("window.x"))
    y = _trusted_geometry_value(fields.get("window.y"))
    width = _trusted_geometry_value(fields.get("window.width"))
    height = _trusted_geometry_value(fields.get("window.height"))
    if x is None or y is None or width is None or height is None:
        return None
    if width <= 0 or height <= 0:
        return None
    if x < snapshot.root_x or y < snapshot.root_y:
        return None
    if x + width > snapshot.root_x + snapshot.width:
        return None
    if y + height > snapshot.root_y + snapshot.height:
        return None
    return CaptureRegion(x=x, y=y, width=width, height=height)


def _trusted_geometry_value(field: ContextField | None) -> int | None:
    if field is None or not _trusted_geometry_field(field):
        return None
    value = field.value
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _trusted_geometry_field(field: ContextField) -> bool:
    return bool(field.provenance) and all(
        item.source_id in _TRUSTED_GEOMETRY_SOURCES for item in field.provenance
    )


def _crop_snapshot(snapshot: XorgSnapshot, region: CaptureRegion) -> tuple[bytes, int]:
    bytes_per_pixel = snapshot.pixel_format.bytes_per_pixel
    local_x = region.x - snapshot.root_x
    local_y = region.y - snapshot.root_y
    packed_stride = region.width * bytes_per_pixel
    rows: list[bytes] = []
    for row in range(region.height):
        start = (local_y + row) * snapshot.stride + local_x * bytes_per_pixel
        rows.append(snapshot.pixels[start : start + packed_stride])
    return b"".join(rows), packed_stride
