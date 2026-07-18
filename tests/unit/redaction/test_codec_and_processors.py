from __future__ import annotations

import threading
from dataclasses import dataclass
from uuid import uuid4

import pytest

from local_recall.domain.frames import OCRResult, RawFrame
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.redaction import PixelRegion
from local_recall.pipeline import PipelineCancellationToken, RawStageItem
from local_recall.ports.ocr import OCRRequest
from local_recall.redaction import (
    DeterministicRedactionPolicy,
    LocalOCRStageProcessor,
    PrePersistenceRedactionStageProcessor,
    RedactionFailure,
    decode_analyzed_stage,
    decode_raw_stage,
    decode_redacted_stage,
    encode_raw_frame,
)

from .support import gray_frame, ocr


@dataclass
class SyntheticOCRProvider:
    result: OCRResult
    calls: int = 0

    @property
    def provider_id(self) -> str:
        return "synthetic-local"

    async def recognize(self, request: OCRRequest) -> OCRResult:
        assert request.frame.frame_id == self.result.frame_id
        self.calls += 1
        return self.result


def _token() -> PipelineCancellationToken:
    return PipelineCancellationToken(CaptureGeneration(1), threading.Event())


def _raw_item(secret: str) -> tuple[RawStageItem, RawFrame]:
    record_id = uuid4()
    frame = gray_frame(
        width=len(secret),
        height=1,
        pixels=secret.encode(),
        frame_id=record_id,
    )
    header, pixels = encode_raw_frame(frame)
    item = RawStageItem(
        record_id=record_id,
        generation=frame.generation,
        configuration_revision="config-v1",
        deadline_monotonic_ns=999_999_999_999_999,
        frames=(bytearray(header), bytearray(pixels)),
    )
    return item, frame


def test_stage_processors_keep_raw_ocr_memory_only_and_emit_redacted_payload() -> None:
    secret = "".join(("pass", "word", "=", "synthetic-", "passphrase"))
    raw_item, frame = _raw_item(secret)
    recognized = ocr(frame, (secret, 0.99, PixelRegion(0, 0, len(secret), 1)))
    provider = SyntheticOCRProvider(recognized)

    analyzed_item = LocalOCRStageProcessor(provider).process(raw_item, _token())
    analyzed = decode_analyzed_stage(analyzed_item)

    assert provider.calls == 1
    assert analyzed.ocr.blocks[0].text == secret
    assert secret not in repr(analyzed_item)

    redacted_item = PrePersistenceRedactionStageProcessor(DeterministicRedactionPolicy()).process(
        analyzed_item, _token()
    )
    redacted = decode_redacted_stage(redacted_item)

    assert redacted.record_id == raw_item.record_id
    assert redacted.frame.ocr_text == ("password=[REDACTED]",)
    assert redacted.frame.pixels == bytes(len(secret))
    assert secret.encode() not in b"".join(redacted_item.frames)
    assert secret not in repr(redacted_item)


def test_codec_rejects_record_identity_changes() -> None:
    frame = gray_frame(width=4, height=1, pixels=b"abcd")
    header, pixels = encode_raw_frame(frame)
    item = RawStageItem(
        record_id=uuid4(),
        generation=frame.generation,
        configuration_revision="config-v1",
        deadline_monotonic_ns=999_999_999_999_999,
        frames=(bytearray(header), bytearray(pixels)),
    )

    with pytest.raises(RedactionFailure, match="frame_mismatch"):
        decode_raw_stage(item)


def test_codec_failure_does_not_echo_unredacted_payload() -> None:
    marker = "RAW-OCR-MARKER-MUST-NOT-LEAK"
    record_id = uuid4()
    item = RawStageItem(
        record_id=record_id,
        generation=CaptureGeneration(1),
        configuration_revision="config-v1",
        deadline_monotonic_ns=999_999_999_999_999,
        frames=(bytearray(marker.encode()), bytearray(b"pixels")),
    )

    with pytest.raises(RedactionFailure) as captured:
        decode_raw_stage(item)

    assert str(record_id) in str(captured.value)
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)
