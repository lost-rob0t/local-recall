from __future__ import annotations

import zlib

from local_recall.capture.png import (
    MAX_PNG_DIMENSION,
    MAX_PNG_PIXEL_BYTES,
    PngDecodeError,
    decode_png_rgb8,
    encode_png_rgb8,
)

_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    return (
        len(data).to_bytes(4, "big")
        + chunk_type
        + data
        + zlib.crc32(chunk_type + data).to_bytes(4, "big")
    )


def _ihdr(
    width: int, height: int, color_type: int, bit_depth: int = 8, interlace: int = 0
) -> bytes:
    return (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes([bit_depth, color_type, 0, 0, interlace])
    )


def _color_png(width: int, height: int, color_type: int) -> bytes:
    channels = {0: 1, 2: 3, 6: 4}[color_type]
    raw = bytearray()
    for _ in range(height):
        raw.append(0)
        for column in range(width):
            value = (column * 17 + 5) % 256
            raw.extend(bytes([value] * channels))
    payload = zlib.compress(bytes(raw))
    return (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(width, height, color_type))
        + _chunk(b"IDAT", payload)
        + _chunk(b"IEND", b"")
    )


def test_exported_bounds_match_documented_limits() -> None:
    assert MAX_PNG_PIXEL_BYTES == 512 * 1024 * 1024
    assert MAX_PNG_DIMENSION == 32_768


def test_round_trip_rgb8_pixels() -> None:
    width, height = 3, 2
    stride = width * 3
    pixels = bytes(range(stride * height))
    encoded = encode_png_rgb8(width=width, height=height, stride=stride, pixels=pixels)
    decoded = decode_png_rgb8(encoded)
    assert decoded.width == width
    assert decoded.height == height
    assert decoded.stride == stride
    assert decoded.pixels == pixels


def test_gray8_png_expands_to_rgb8() -> None:
    width, height = 2, 2
    raw = bytearray()
    for _ in range(height):
        raw.append(0)
        raw.extend(bytes([7, 200]))
    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(width, height, 0))
        + _chunk(b"IDAT", zlib.compress(bytes(raw)))
        + _chunk(b"IEND", b"")
    )
    decoded = decode_png_rgb8(encoded)
    assert decoded.width == width
    assert decoded.height == height
    assert decoded.stride == width * 3
    assert decoded.pixels == bytes([7, 7, 7, 200, 200, 200] * 2)


def test_rgba8_png_drops_alpha_channel() -> None:
    width, height = 1, 2
    raw = bytearray()
    for _ in range(height):
        raw.append(0)
        raw.extend(bytes([1, 2, 3, 255]))
    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(width, height, 6))
        + _chunk(b"IDAT", zlib.compress(bytes(raw)))
        + _chunk(b"IEND", b"")
    )
    decoded = decode_png_rgb8(encoded)
    assert decoded.pixels == bytes([1, 2, 3] * 2)


def test_png_with_sub_and_up_filters_unfilters_correctly() -> None:
    width, height = 3, 2
    row0 = bytes([10, 20, 30, 40, 50, 60, 70, 80, 90])
    row1 = bytes([5, 5, 5, 5, 5, 5, 5, 5, 5])
    pixels = row0 + row1

    filtered = bytearray()
    filtered.append(1)
    filtered.extend(row0[:3])
    for index in range(3, len(row0)):
        filtered.append((row0[index] - row0[index - 3]) & 0xFF)
    filtered.append(2)
    filtered.extend((row1[index] - row0[index]) & 0xFF for index in range(len(row1)))

    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(width, height, 2))
        + _chunk(b"IDAT", zlib.compress(bytes(filtered)))
        + _chunk(b"IEND", b"")
    )
    decoded = decode_png_rgb8(encoded)
    assert decoded.pixels == pixels


def test_average_and_paeth_filters_are_supported() -> None:
    width, height = 2, 3
    row0 = bytes([100, 100, 100, 200, 200, 200])
    row1 = bytes([150, 150, 150, 250, 250, 250])
    row2 = bytes([160, 160, 160, 240, 240, 240])
    pixels = row0 + row1 + row2

    def _average(raw_row: bytes, previous: bytes, bpp: int) -> bytes:
        out = bytearray()
        for index, value in enumerate(raw_row):
            left = raw_row[index - bpp] if index >= bpp else 0
            up = previous[index]
            prediction = (left + up) // 2
            out.append((value - prediction) & 0xFF)
        return bytes(out)

    def _paeth(raw_row: bytes, previous: bytes, bpp: int) -> bytes:
        out = bytearray()
        for index, value in enumerate(raw_row):
            left = raw_row[index - bpp] if index >= bpp else 0
            up = previous[index]
            up_left = previous[index - bpp] if index >= bpp else 0
            base = left + up - up_left
            distances = (abs(base - left), abs(base - up), abs(base - up_left))
            prediction = (left, up, up_left)[distances.index(min(distances))]
            out.append((value - prediction) & 0xFF)
        return bytes(out)

    filtered = bytearray()
    filtered.append(0)
    filtered.extend(row0)
    filtered.append(3)
    filtered.extend(_average(row1, row0, 3))
    filtered.append(4)
    filtered.extend(_paeth(row2, row1, 3))

    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(width, height, 2))
        + _chunk(b"IDAT", zlib.compress(bytes(filtered)))
        + _chunk(b"IEND", b"")
    )
    decoded = decode_png_rgb8(encoded)
    assert decoded.pixels == pixels


def test_explicit_dimension_bounds_are_enforced() -> None:
    encoded = _color_png(3, 2, 2)
    attempts = (
        lambda: decode_png_rgb8(encoded, max_width=2),
        lambda: decode_png_rgb8(encoded, max_height=1),
    )
    for attempt in attempts:
        try:
            attempt()
        except PngDecodeError as error:
            assert error.reason_code == "png-dimension-bound-exceeded"
        else:
            raise AssertionError("dimension bound was not enforced")


def test_output_bound_is_enforced() -> None:
    encoded = _color_png(4, 4, 2)
    try:
        decode_png_rgb8(encoded, max_output_bytes=8)
    except PngDecodeError as error:
        assert error.reason_code == "png-output-bound-exceeded"
    else:
        raise AssertionError("output bound was not enforced")


def test_bad_signature_is_rejected() -> None:
    try:
        decode_png_rgb8(b"\x00PNG garbage-data" * 4)
    except PngDecodeError as error:
        assert error.reason_code == "png-signature-invalid"
    else:
        raise AssertionError("bad signature was accepted")


def test_truncated_payload_is_rejected() -> None:
    encoded = _color_png(2, 2, 2)
    try:
        decode_png_rgb8(encoded[:-4])
    except PngDecodeError as error:
        assert error.reason_code == "png-chunk-truncated"
    else:
        raise AssertionError("truncated payload was accepted")


def test_bad_chunk_crc_is_rejected() -> None:
    encoded = bytearray(_color_png(2, 2, 2))
    encoded[-1] ^= 0xFF
    try:
        decode_png_rgb8(bytes(encoded))
    except PngDecodeError as error:
        assert error.reason_code == "png-chunk-crc-invalid"
    else:
        raise AssertionError("bad crc was accepted")


def test_interlaced_png_is_rejected() -> None:
    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(2, 2, 2, interlace=1))
        + _chunk(b"IDAT", zlib.compress(b"\x00" * 12))
        + _chunk(b"IEND", b"")
    )
    try:
        decode_png_rgb8(encoded)
    except PngDecodeError as error:
        assert error.reason_code == "png-interlace-unsupported"
    else:
        raise AssertionError("interlaced payload was accepted")


def test_palette_png_is_rejected() -> None:
    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(2, 2, 3))
        + _chunk(b"IDAT", zlib.compress(b"\x00" * 4))
        + _chunk(b"IEND", b"")
    )
    try:
        decode_png_rgb8(encoded)
    except PngDecodeError as error:
        assert error.reason_code == "png-color-type-unsupported"
    else:
        raise AssertionError("palette payload was accepted")


def test_sixteen_bit_png_is_rejected() -> None:
    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(2, 2, 2, bit_depth=16))
        + _chunk(b"IDAT", zlib.compress(b"\x00" * 12))
        + _chunk(b"IEND", b"")
    )
    try:
        decode_png_rgb8(encoded)
    except PngDecodeError as error:
        assert error.reason_code == "png-bit-depth-unsupported"
    else:
        raise AssertionError("16-bit payload was accepted")


def test_pixel_payload_size_mismatch_is_rejected() -> None:
    encoded = (
        _SIGNATURE
        + _chunk(b"IHDR", _ihdr(2, 2, 2))
        + _chunk(b"IDAT", zlib.compress(b"\x00" * 6))
        + _chunk(b"IEND", b"")
    )
    try:
        decode_png_rgb8(encoded)
    except PngDecodeError as error:
        assert error.reason_code == "png-pixel-payload-invalid"
    else:
        raise AssertionError("size mismatch was accepted")


def test_compression_bomb_output_is_bounded() -> None:
    encoded = bytearray(_color_png(2, 2, 2))
    type_index = encoded.index(b"IDAT")
    length = int.from_bytes(encoded[type_index - 4 : type_index], "big")
    start = type_index + 4
    end = start + length
    bomb = zlib.compress(b"\x00" * 4_000_000)
    rebuilt = bytearray(encoded[: type_index - 4])
    rebuilt.extend(len(bomb).to_bytes(4, "big"))
    rebuilt.extend(b"IDAT")
    rebuilt.extend(bomb)
    rebuilt.extend(zlib.crc32(b"IDAT" + bomb).to_bytes(4, "big"))
    rebuilt.extend(encoded[end + 4 :])
    try:
        decode_png_rgb8(bytes(rebuilt), max_output_bytes=1024)
    except PngDecodeError as error:
        assert error.reason_code == "png-pixel-payload-invalid"
    else:
        raise AssertionError("inflation was not bounded")


def test_trailing_data_after_iend_is_rejected() -> None:
    encoded = _color_png(2, 2, 2) + b"trailing"
    try:
        decode_png_rgb8(encoded)
    except PngDecodeError as error:
        assert error.reason_code == "png-trailing-data"
    else:
        raise AssertionError("trailing data was accepted")


def test_decoded_image_repr_is_content_free() -> None:
    marker = b"synthetic-pixel-secret"
    pixels = marker + b"\x00" * (8 * 3 - len(marker))
    encoded = encode_png_rgb8(width=8, height=1, stride=24, pixels=pixels)
    decoded = decode_png_rgb8(encoded)
    assert marker.decode("ascii", errors="replace") not in repr(decoded)


def test_decode_error_messages_are_fixed_reason_codes() -> None:
    try:
        decode_png_rgb8(b"short")
    except PngDecodeError as error:
        assert str(error) == error.reason_code
    else:
        raise AssertionError("short payload was accepted")
