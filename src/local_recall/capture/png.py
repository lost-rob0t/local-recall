"""Bounded in-memory PNG codec for portal screenshot payloads."""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_CHUNK_HEADER_BYTES = 8
_CHUNK_TRAILER_BYTES = 4
_IHDR_TYPE = b"IHDR"
_IDAT_TYPE = b"IDAT"
_IEND_TYPE = b"IEND"
_MAX_DIMENSION = 32_768
_MAX_PIXEL_BYTES = 512 * 1024 * 1024
_FILTER_NONE = 0
_FILTER_SUB = 1
_FILTER_UP = 2
_FILTER_AVERAGE = 3
_FILTER_PAETH = 4
_CHANNELS = {0: 1, 2: 3, 6: 4}

MAX_PNG_DIMENSION = _MAX_DIMENSION
MAX_PNG_PIXEL_BYTES = _MAX_PIXEL_BYTES


class PngDecodeError(ValueError):
    """Content-free PNG decode failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class PngImage:
    width: int
    height: int
    stride: int
    pixels: bytes = field(repr=False)


def decode_png_rgb8(
    payload: bytes | bytearray,
    *,
    max_width: int = _MAX_DIMENSION,
    max_height: int = _MAX_DIMENSION,
    max_output_bytes: int = _MAX_PIXEL_BYTES,
) -> PngImage:
    """Decode an 8-bit grayscale/RGB/RGBA PNG into an RGB8 image."""
    if not 0 < max_width <= _MAX_DIMENSION or not 0 < max_height <= _MAX_DIMENSION:
        raise PngDecodeError("png-bound-invalid")
    if not 0 < max_output_bytes <= _MAX_PIXEL_BYTES:
        raise PngDecodeError("png-bound-invalid")
    data = memoryview(payload)
    ihdr = _Ihdr.parse(data, max_width, max_height)
    expected_rgb = ihdr.width * 3 * ihdr.height
    if expected_rgb > max_output_bytes:
        raise PngDecodeError("png-output-bound-exceeded")
    raw = _inflate_pixel_stream(data, ihdr)
    pixels = _unfilter_and_convert(raw, ihdr)
    return PngImage(
        width=ihdr.width,
        height=ihdr.height,
        stride=ihdr.width * 3,
        pixels=pixels,
    )


@dataclass(frozen=True, slots=True)
class _Ihdr:
    width: int
    height: int
    channels: int

    @classmethod
    def parse(cls, data: memoryview, max_width: int, max_height: int) -> _Ihdr:
        if len(data) < _CHUNK_HEADER_BYTES + len(_SIGNATURE):
            raise PngDecodeError("png-signature-invalid")
        if bytes(data[:8]) != _SIGNATURE:
            raise PngDecodeError("png-signature-invalid")
        offset = len(_SIGNATURE)
        chunk_type, chunk_data, offset = _read_chunk(data, offset)
        if chunk_type != _IHDR_TYPE or len(chunk_data) != 13:
            raise PngDecodeError("png-header-invalid")
        width = int.from_bytes(chunk_data[0:4], "big")
        height = int.from_bytes(chunk_data[4:8], "big")
        bit_depth = chunk_data[8]
        color_type = chunk_data[9]
        compression = chunk_data[10]
        filter_method = chunk_data[11]
        interlace = chunk_data[12]
        if not 0 < width <= max_width or not 0 < height <= max_height:
            raise PngDecodeError("png-dimension-bound-exceeded")
        if color_type not in _CHANNELS:
            raise PngDecodeError("png-color-type-unsupported")
        if bit_depth != 8:
            raise PngDecodeError("png-bit-depth-unsupported")
        if compression != 0 or filter_method != 0:
            raise PngDecodeError("png-header-invalid")
        if interlace != 0:
            raise PngDecodeError("png-interlace-unsupported")
        return cls(width=width, height=height, channels=_CHANNELS[color_type])


def _inflate_pixel_stream(data: memoryview, ihdr: _Ihdr) -> bytes:
    idat_parts: list[memoryview] = []
    offset = len(_SIGNATURE) + _CHUNK_HEADER_BYTES + 13 + _CHUNK_TRAILER_BYTES
    saw_iend = False
    while offset < len(data):
        chunk_type, chunk_data, offset = _read_chunk(data, offset)
        if chunk_type == _IEND_TYPE:
            saw_iend = True
            break
        if chunk_type == _IDAT_TYPE:
            idat_parts.append(chunk_data)
    if not saw_iend:
        raise PngDecodeError("png-chunk-truncated")
    if offset < len(data):
        raise PngDecodeError("png-trailing-data")
    if not idat_parts:
        raise PngDecodeError("png-pixel-payload-invalid")
    expected_raw = ihdr.height * (1 + ihdr.width * ihdr.channels)
    decompressor = zlib.decompressobj()
    raw = bytearray()
    limit = expected_raw + 1
    for part in idat_parts:
        raw.extend(decompressor.decompress(part, limit - len(raw)))
        if len(raw) >= limit:
            raise PngDecodeError("png-pixel-payload-invalid")
    if not decompressor.eof or decompressor.unused_data:
        raise PngDecodeError("png-pixel-payload-invalid")
    if len(raw) != expected_raw:
        raise PngDecodeError("png-pixel-payload-invalid")
    return bytes(raw)


def _read_chunk(data: memoryview, offset: int) -> tuple[bytes, memoryview, int]:
    if offset + _CHUNK_HEADER_BYTES > len(data):
        raise PngDecodeError("png-chunk-truncated")
    length = int.from_bytes(data[offset : offset + 4], "big")
    chunk_type = bytes(data[offset + 4 : offset + 8])
    start = offset + _CHUNK_HEADER_BYTES
    end = start + length
    if end + _CHUNK_TRAILER_BYTES > len(data):
        raise PngDecodeError("png-chunk-truncated")
    chunk_data = data[start:end]
    expected_crc = int.from_bytes(data[end : end + _CHUNK_TRAILER_BYTES], "big")
    if zlib.crc32(bytes(data[offset + 4 : end])) != expected_crc:
        raise PngDecodeError("png-chunk-crc-invalid")
    return chunk_type, chunk_data, end + _CHUNK_TRAILER_BYTES


def _unfilter_and_convert(raw: bytes, ihdr: _Ihdr) -> bytes:
    channels = ihdr.channels
    row_bytes = ihdr.width * channels
    previous = bytearray(row_bytes)
    target = bytearray(ihdr.width * 3 * ihdr.height)
    target_offset = 0
    for row in range(ihdr.height):
        start = row * (1 + row_bytes)
        filter_code = raw[start]
        current = bytearray(raw[start + 1 : start + 1 + row_bytes])
        if filter_code == _FILTER_NONE:
            pass
        elif filter_code == _FILTER_SUB:
            for index in range(channels, row_bytes):
                current[index] = (current[index] + current[index - channels]) & 0xFF
        elif filter_code == _FILTER_UP:
            for index in range(row_bytes):
                current[index] = (current[index] + previous[index]) & 0xFF
        elif filter_code == _FILTER_AVERAGE:
            for index in range(row_bytes):
                left = current[index - channels] if index >= channels else 0
                prediction = (left + previous[index]) // 2
                current[index] = (current[index] + prediction) & 0xFF
        elif filter_code == _FILTER_PAETH:
            for index in range(row_bytes):
                left = current[index - channels] if index >= channels else 0
                up = previous[index]
                up_left = previous[index - channels] if index >= channels else 0
                current[index] = (current[index] + _paeth(left, up, up_left)) & 0xFF
        else:
            raise PngDecodeError("png-filter-unsupported")
        target_offset = _write_rgb8_row(target, target_offset, current, channels)
        previous = current
    return bytes(target)


def _write_rgb8_row(target: bytearray, offset: int, row: bytearray, channels: int) -> int:
    if channels == 2:
        raise PngDecodeError("png-color-type-unsupported")
    if channels == 1:
        for value in row:
            target[offset] = value
            target[offset + 1] = value
            target[offset + 2] = value
            offset += 3
        return offset
    if channels == 3:
        target[offset : offset + len(row)] = row
        return offset + len(row)
    for index in range(0, len(row), 4):
        target[offset] = row[index]
        target[offset + 1] = row[index + 1]
        target[offset + 2] = row[index + 2]
        offset += 3
    return offset


def _paeth(left: int, up: int, up_left: int) -> int:
    base = left + up - up_left
    distance_left = abs(base - left)
    distance_up = abs(base - up)
    distance_up_left = abs(base - up_left)
    if distance_left <= distance_up and distance_left <= distance_up_left:
        return left
    if distance_up <= distance_up_left:
        return up
    return up_left


def encode_png_rgb8(*, width: int, height: int, stride: int, pixels: bytes) -> bytes:
    """Encode an RGB8 buffer as a minimal PNG (support helper for tests and fakes)."""
    row_bytes = width * 3
    if width <= 0 or height <= 0 or width > _MAX_DIMENSION or height > _MAX_DIMENSION:
        raise ValueError("png encode dimensions out of bounds")
    if stride < row_bytes:
        raise ValueError("png encode stride is smaller than pixel width")
    if len(pixels) != stride * height:
        raise ValueError("png encode buffer size mismatch")
    ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    raw = bytearray()
    for row in range(height):
        raw.append(_FILTER_NONE)
        raw.extend(pixels[row * stride : row * stride + row_bytes])
    idat = zlib.compress(bytes(raw), 6)
    return (
        _SIGNATURE + _chunk(_IHDR_TYPE, ihdr) + _chunk(_IDAT_TYPE, idat) + _chunk(_IEND_TYPE, b"")
    )


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    return (
        len(data).to_bytes(4, "big")
        + chunk_type
        + data
        + zlib.crc32(chunk_type + data).to_bytes(4, "big")
    )
