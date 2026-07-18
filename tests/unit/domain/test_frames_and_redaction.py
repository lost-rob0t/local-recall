from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.domain.frames import (
    OCRBlock,
    OCRResult,
    PixelFormat,
    RawFrame,
    RedactedFrame,
    RedactedRecord,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata, SourceConfidence
from local_recall.domain.redaction import (
    PixelRegion,
    RedactionAction,
    RedactionFinding,
    RedactionKind,
    RedactionReason,
    RedactionTarget,
    TextSpan,
)


def metadata() -> ContextMetadata:
    return ContextMetadata(observed_at=datetime.now(UTC), fields=())


def raw_frame() -> RawFrame:
    return RawFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=datetime.now(UTC),
        width=2,
        height=1,
        stride=8,
        pixel_format=PixelFormat.RGBA8,
        pixels=b"12345678",
        metadata=metadata(),
    )


def test_raw_frame_validates_buffer_size() -> None:
    with pytest.raises(ValueError, match="pixel buffer"):
        RawFrame(
            frame_id=uuid4(),
            generation=CaptureGeneration(1),
            captured_at=datetime.now(UTC),
            width=2,
            height=1,
            stride=8,
            pixel_format=PixelFormat.RGBA8,
            pixels=b"short",
            metadata=metadata(),
        )


def test_raw_frame_repr_hides_pixels() -> None:
    assert "12345678" not in repr(raw_frame())


def test_redaction_finding_never_stores_matched_content() -> None:
    finding = RedactionFinding(
        finding_id=uuid4(),
        target=RedactionTarget.OCR_TEXT,
        kind=RedactionKind.API_TOKEN,
        reason=RedactionReason.DETERMINISTIC_DETECTOR,
        action=RedactionAction.REPLACE_TEXT,
        detector_id="token-pattern-v1",
        confidence=SourceConfidence(1.0),
        text_span=TextSpan(0, 8),
    )

    assert not hasattr(finding, "matched_text")
    assert not hasattr(finding, "value")


def test_redaction_location_must_match_target() -> None:
    with pytest.raises(ValueError, match="text span"):
        RedactionFinding(
            finding_id=uuid4(),
            target=RedactionTarget.OCR_TEXT,
            kind=RedactionKind.API_TOKEN,
            reason=RedactionReason.DETERMINISTIC_DETECTOR,
            action=RedactionAction.REPLACE_TEXT,
            detector_id="token-pattern-v1",
            confidence=SourceConfidence(1.0),
            pixel_region=PixelRegion(0, 0, 1, 1),
        )


def test_redacted_record_is_a_distinct_stage_type() -> None:
    finding = RedactionFinding(
        finding_id=uuid4(),
        target=RedactionTarget.PIXELS,
        kind=RedactionKind.POLICY,
        reason=RedactionReason.POLICY_RULE,
        action=RedactionAction.MASK_PIXELS,
        detector_id="synthetic-policy",
        confidence=SourceConfidence(1.0),
        pixel_region=PixelRegion(0, 0, 1, 1),
    )
    frame = RedactedFrame(
        frame_id=uuid4(),
        generation=CaptureGeneration(1),
        captured_at=datetime.now(UTC),
        width=2,
        height=1,
        stride=8,
        pixel_format=PixelFormat.RGBA8,
        pixels=b"XXXXXXXX",
        metadata=metadata(),
        ocr_text=("[REDACTED]",),
        findings=(finding,),
        policy_revision="policy-v1",
    )
    record = RedactedRecord(record_id=uuid4(), frame=frame, created_at=datetime.now(UTC))

    assert isinstance(record, RedactedRecord)
    assert not isinstance(record, RawFrame)
    assert "XXXXXXXX" not in repr(record)


def test_ocr_result_rejects_mismatched_frame_id() -> None:
    with pytest.raises(ValueError, match="same frame"):
        OCRResult(
            frame_id=uuid4(),
            blocks=(
                OCRBlock(
                    block_id=uuid4(),
                    frame_id=uuid4(),
                    text="synthetic",
                    confidence=SourceConfidence(0.8),
                    region=PixelRegion(0, 0, 1, 1),
                ),
            ),
        )
