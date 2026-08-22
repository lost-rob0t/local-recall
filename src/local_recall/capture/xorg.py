"""Xorg desktop capture boundary."""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
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
_XWD_HEADER_BYTES = 100
_XWD_COLOR_BYTES = 12
_XWD_VERSION = 7
_XWD_ZPIXMAP = 2
_XWD_TRUE_COLOR = 4
_XWD_LSB_FIRST = 0
_XWD_MSB_FIRST = 1
_XWD_BACKEND_REVISION = "xwd-zpixmap-v1"


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


@runtime_checkable
class NativeXorgRunner(Protocol):
    async def capture_root_dump(self, *, deadline_monotonic_ns: int) -> bytes: ...

    async def monitor_layout(
        self, *, deadline_monotonic_ns: int
    ) -> tuple[XorgMonitor, ...]: ...


class XwdSnapshotReader:
    """Decode an in-memory XWD root dump behind a bounded native runner."""

    def __init__(
        self,
        *,
        runner: NativeXorgRunner,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._runner = runner
        self._now = now

    async def capture_root(self, *, deadline_monotonic_ns: int) -> XorgSnapshot:
        before = await self._runner.monitor_layout(deadline_monotonic_ns=deadline_monotonic_ns)
        payload = await self._runner.capture_root_dump(deadline_monotonic_ns=deadline_monotonic_ns)
        after = await self._runner.monitor_layout(deadline_monotonic_ns=deadline_monotonic_ns)
        if before != after:
            raise XorgCaptureError("display-changed")
        if not before:
            raise XorgCaptureError("display-unavailable")
        try:
            decoded = _decode_xwd(payload)
            _validate_monitors(before, decoded.root_x, decoded.root_y, decoded.width, decoded.height)
        except XorgCaptureError:
            raise
        except (OverflowError, ValueError, struct.error):
            raise XorgCaptureError("capture-format-invalid") from None
        return XorgSnapshot(
            captured_at=self._now(),
            root_x=decoded.root_x,
            root_y=decoded.root_y,
            width=decoded.width,
            height=decoded.height,
            stride=decoded.stride,
            pixel_format=PixelFormat.RGB8,
            pixels=decoded.pixels,
            monitors=before,
            backend_revision=_XWD_BACKEND_REVISION,
        )


@dataclass(frozen=True, slots=True)
class _DecodedXwd:
    root_x: int
    root_y: int
    width: int
    height: int
    stride: int
    pixels: bytes


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


def _decode_xwd(payload: bytes) -> _DecodedXwd:
    if len(payload) < _XWD_HEADER_BYTES:
        raise ValueError("short header")
    values = struct.unpack(">25I", payload[:_XWD_HEADER_BYTES])
    (
        header_size,
        version,
        pixmap_format,
        depth,
        width,
        height,
        xoffset,
        byte_order,
        _bitmap_unit,
        _bitmap_bit_order,
        _bitmap_pad,
        bits_per_pixel,
        bytes_per_line,
        visual_class,
        red_mask,
        green_mask,
        blue_mask,
        _bits_per_rgb,
        _colormap_entries,
        ncolors,
        window_width,
        window_height,
        window_x,
        window_y,
        _window_border_width,
    ) = values

    if version != _XWD_VERSION or pixmap_format != _XWD_ZPIXMAP:
        raise ValueError("unsupported xwd version or pixmap format")
    if visual_class != _XWD_TRUE_COLOR or depth <= 0 or depth > 32:
        raise ValueError("unsupported xwd visual")
    if not 0 < width <= _MAX_DIMENSION or not 0 < height <= _MAX_DIMENSION:
        raise ValueError("xwd dimensions out of bounds")
    if window_width != width or window_height != height or xoffset != 0:
        raise ValueError("xwd root geometry mismatch")
    if header_size < _XWD_HEADER_BYTES + 1 or header_size > len(payload):
        raise ValueError("xwd header size invalid")
    if payload[header_size - 1] != 0:
        raise ValueError("xwd window name is not terminated")
    if ncolors > 65_536:
        raise ValueError("xwd color table too large")
    color_bytes = ncolors * _XWD_COLOR_BYTES
    image_offset = header_size + color_bytes
    if image_offset > len(payload):
        raise ValueError("xwd color table truncated")
    if bits_per_pixel not in (16, 24, 32) or bits_per_pixel % 8 != 0:
        raise ValueError("xwd pixel width unsupported")
    source_bytes_per_pixel = bits_per_pixel // 8
    if bytes_per_line < width * source_bytes_per_pixel:
        raise ValueError("xwd stride too small")
    source_size = bytes_per_line * height
    if source_size > _MAX_PIXEL_BYTES or len(payload) - image_offset != source_size:
        raise ValueError("xwd pixel payload invalid")
    if byte_order not in (_XWD_LSB_FIRST, _XWD_MSB_FIRST):
        raise ValueError("xwd byte order invalid")
    _validate_color_masks(red_mask, green_mask, blue_mask, bits_per_pixel)

    source = memoryview(payload)[image_offset:]
    stride = width * PixelFormat.RGB8.bytes_per_pixel
    target_size = stride * height
    if target_size > _MAX_PIXEL_BYTES:
        raise ValueError("decoded pixel payload too large")
    target = bytearray(target_size)
    target_index = 0
    order = "little" if byte_order == _XWD_LSB_FIRST else "big"
    for row in range(height):
        row_start = row * bytes_per_line
        for column in range(width):
            pixel_start = row_start + column * source_bytes_per_pixel
            pixel_value = int.from_bytes(
                source[pixel_start : pixel_start + source_bytes_per_pixel], order
            )
            target[target_index] = _scale_masked_channel(pixel_value, red_mask)
            target[target_index + 1] = _scale_masked_channel(pixel_value, green_mask)
            target[target_index + 2] = _scale_masked_channel(pixel_value, blue_mask)
            target_index += 3

    return _DecodedXwd(
        root_x=_signed_card32(window_x),
        root_y=_signed_card32(window_y),
        width=width,
        height=height,
        stride=stride,
        pixels=bytes(target),
    )


def _validate_color_masks(red: int, green: int, blue: int, bits_per_pixel: int) -> None:
    masks = (red, green, blue)
    if any(mask == 0 or mask.bit_length() > bits_per_pixel for mask in masks):
        raise ValueError("xwd color mask invalid")
    if red & green or red & blue or green & blue:
        raise ValueError("xwd color masks overlap")
    for mask in masks:
        shift = (mask & -mask).bit_length() - 1
        normalized = mask >> shift
        if normalized & (normalized + 1):
            raise ValueError("xwd color mask is not contiguous")


def _scale_masked_channel(pixel: int, mask: int) -> int:
    shift = (mask & -mask).bit_length() - 1
    maximum = mask >> shift
    value = (pixel & mask) >> shift
    return (value * 255 + maximum // 2) // maximum


def _signed_card32(value: int) -> int:
    return value - (1 << 32) if value & (1 << 31) else value


def _validate_monitors(
    monitors: tuple[XorgMonitor, ...], root_x: int, root_y: int, width: int, height: int
) -> None:
    root_right = root_x + width
    root_bottom = root_y + height
    for monitor in monitors:
        monitor.to_domain()
        if monitor.x < root_x or monitor.y < root_y:
            raise ValueError("monitor lies outside root")
        if monitor.x + monitor.width > root_right or monitor.y + monitor.height > root_bottom:
            raise ValueError("monitor lies outside root")
