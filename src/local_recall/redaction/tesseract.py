from __future__ import annotations

import asyncio
import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import uuid4

from local_recall.config.models import OCRSettings
from local_recall.domain.frames import OCRBlock, OCRResult, PixelFormat, RawFrame
from local_recall.domain.metadata import SourceConfidence
from local_recall.domain.redaction import PixelRegion
from local_recall.ports.ocr import OCRRequest

from .errors import LocalOCRFailure, OCRFailureCode


@dataclass(frozen=True, slots=True, repr=False)
class OCRCommandResult:
    return_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(default=b"", repr=False)

    def __repr__(self) -> str:
        return (
            f"OCRCommandResult(return_code={self.return_code}, "
            f"stdout_bytes={len(self.stdout)}, stderr_bytes={len(self.stderr)})"
        )


@runtime_checkable
class OCRCommandRunner(Protocol):
    async def run(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes,
        timeout_seconds: float,
    ) -> OCRCommandResult: ...


class LocalSubprocessOCRRunner:
    async def run(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes,
        timeout_seconds: float,
    ) -> OCRCommandResult:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, PermissionError) as exc:
            raise _RunnerUnavailable from exc
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_bytes), timeout=timeout_seconds
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise _RunnerTimeout from exc
        return OCRCommandResult(process.returncode or 0, stdout, stderr)


class _RunnerUnavailable(RuntimeError):
    pass


class _RunnerTimeout(RuntimeError):
    pass


class TesseractOCRProvider:
    """Local-only OCR provider using Tesseract stdin/stdout with no temporary files."""

    def __init__(
        self,
        settings: OCRSettings | None = None,
        *,
        runner: OCRCommandRunner | None = None,
    ) -> None:
        self._settings = settings or OCRSettings()
        self._runner = runner or LocalSubprocessOCRRunner()

    @property
    def provider_id(self) -> str:
        return self._settings.provider_id

    @property
    def network_capable(self) -> bool:
        return False

    async def recognize(self, request: OCRRequest) -> OCRResult:
        frame = request.frame
        image = encode_portable_anymap(frame)
        if len(image) > self._settings.max_input_bytes:
            raise LocalOCRFailure(frame.frame_id, OCRFailureCode.INPUT_TOO_LARGE)
        languages = request.language_hints or self._settings.languages
        if not _valid_runtime_languages(languages):
            raise LocalOCRFailure(frame.frame_id, OCRFailureCode.EXECUTION_FAILED)
        argv = (
            self._settings.executable,
            "stdin",
            "stdout",
            "-l",
            "+".join(languages),
            "tsv",
        )
        try:
            result = await self._runner.run(
                argv,
                input_bytes=image,
                timeout_seconds=self._settings.timeout_seconds,
            )
        except _RunnerUnavailable as exc:
            raise LocalOCRFailure(frame.frame_id, OCRFailureCode.EXECUTABLE_UNAVAILABLE) from exc
        except _RunnerTimeout as exc:
            raise LocalOCRFailure(frame.frame_id, OCRFailureCode.TIMEOUT) from exc
        except LocalOCRFailure:
            raise
        except Exception as exc:
            raise LocalOCRFailure(frame.frame_id, OCRFailureCode.EXECUTION_FAILED) from exc
        if result.return_code != 0:
            raise LocalOCRFailure(frame.frame_id, OCRFailureCode.EXECUTION_FAILED)
        return parse_tesseract_tsv(frame, result.stdout)


def encode_portable_anymap(frame: RawFrame) -> bytes:
    if frame.pixel_format is PixelFormat.GRAY8:
        header = f"P5\n{frame.width} {frame.height}\n255\n".encode("ascii")
        rows: list[bytes] = []
        for y in range(frame.height):
            start = y * frame.stride
            rows.append(frame.pixels[start : start + frame.width])
        return header + b"".join(rows)

    header = f"P6\n{frame.width} {frame.height}\n255\n".encode("ascii")
    rows: list[bytes] = []
    bytes_per_pixel = frame.pixel_format.bytes_per_pixel
    for y in range(frame.height):
        row_start = y * frame.stride
        if frame.pixel_format is PixelFormat.RGB8:
            rows.append(frame.pixels[row_start : row_start + frame.width * 3])
            continue
        row = bytearray(frame.width * 3)
        for x in range(frame.width):
            source = row_start + x * bytes_per_pixel
            destination = x * 3
            row[destination : destination + 3] = frame.pixels[source : source + 3]
        rows.append(bytes(row))
    return header + b"".join(rows)


def parse_tesseract_tsv(frame: RawFrame, payload: bytes) -> OCRResult:
    try:
        text = payload.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text), delimiter="\t")
        required = {"left", "top", "width", "height", "conf", "text"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError("missing OCR columns")
        blocks: list[OCRBlock] = []
        for row in reader:
            value = (row.get("text") or "").strip()
            if not value:
                continue
            confidence_value = float(row["conf"])
            if confidence_value < 0:
                continue
            left = int(row["left"])
            top = int(row["top"])
            width = int(row["width"])
            height = int(row["height"])
            region = PixelRegion(left, top, width, height)
            if region.x + region.width > frame.width or region.y + region.height > frame.height:
                raise ValueError("OCR region is outside the frame")
            blocks.append(
                OCRBlock(
                    block_id=uuid4(),
                    frame_id=frame.frame_id,
                    text=value,
                    confidence=SourceConfidence(min(1.0, confidence_value / 100.0)),
                    region=region,
                )
            )
    except (UnicodeDecodeError, TypeError, ValueError, csv.Error, KeyError) as exc:
        raise LocalOCRFailure(frame.frame_id, OCRFailureCode.MALFORMED_OUTPUT) from exc
    return OCRResult(frame_id=frame.frame_id, blocks=tuple(blocks))


def _valid_runtime_languages(languages: tuple[str, ...]) -> bool:
    return bool(languages) and all(
        language and all(character in _LANGUAGE_CHARACTERS for character in language)
        for language in languages
    )


_LANGUAGE_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789_+-"
)


def executable_name(settings: OCRSettings) -> str:
    return Path(settings.executable).name
