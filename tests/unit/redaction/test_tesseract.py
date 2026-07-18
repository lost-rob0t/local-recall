from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from local_recall.config import OCRSettings
from local_recall.ports.ocr import OCRRequest
from local_recall.redaction import (
    LocalOCRFailure,
    OCRCommandResult,
    OCRFailureCode,
    TesseractOCRProvider,
    encode_portable_anymap,
)

from .support import gray_frame


@dataclass
class FakeRunner:
    result: OCRCommandResult
    argv: tuple[str, ...] | None = None
    input_bytes: bytes = field(default=b"", repr=False)
    timeout_seconds: float = 0.0

    async def run(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes,
        timeout_seconds: float,
    ) -> OCRCommandResult:
        self.argv = argv
        self.input_bytes = input_bytes
        self.timeout_seconds = timeout_seconds
        return self.result


def _tsv(text: str = "synthetic") -> bytes:
    return (
        "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"
        f"5\t1\t1\t1\t1\t1\t1\t0\t8\t1\t93.5\t{text}\n"
    ).encode()


def test_tesseract_uses_stdin_stdout_and_returns_typed_regions() -> None:
    frame = gray_frame(width=10, height=2, pixels=bytes(range(20)))
    runner = FakeRunner(OCRCommandResult(0, _tsv()))
    provider = TesseractOCRProvider(
        OCRSettings(timeout_seconds=3.0),
        runner=runner,
    )

    result = asyncio.run(provider.recognize(OCRRequest(frame)))

    assert provider.network_capable is False
    assert runner.argv == ("tesseract", "stdin", "stdout", "-l", "eng", "tsv")
    assert runner.input_bytes.startswith(b"P5\n10 2\n255\n")
    assert runner.timeout_seconds == 3.0
    assert result.blocks[0].text == "synthetic"
    assert abs(result.blocks[0].confidence.value - 0.935) < 1e-9
    assert result.blocks[0].region.x == 1


def test_portable_anymap_strips_stride_padding() -> None:
    frame = gray_frame(width=3, height=2, pixels=b"abcXYZ")

    encoded = encode_portable_anymap(frame)

    assert encoded == b"P5\n3 2\n255\nabcXYZ"


def test_tesseract_failures_are_sanitized() -> None:
    frame = gray_frame(width=10, height=2, pixels=bytes(range(20)))
    marker = "secret-marker-must-not-leak"
    runner = FakeRunner(OCRCommandResult(17, b"", marker.encode()))
    provider = TesseractOCRProvider(runner=runner)

    with pytest.raises(LocalOCRFailure) as captured:
        asyncio.run(provider.recognize(OCRRequest(frame)))

    assert captured.value.code is OCRFailureCode.EXECUTION_FAILED
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)
