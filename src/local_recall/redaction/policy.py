from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from local_recall.config.models import RedactionSettings
from local_recall.domain.frames import OCRBlock, RedactedFrame, RedactedRecord
from local_recall.domain.metadata import ContextField, ContextMetadata, SourceConfidence
from local_recall.domain.redaction import (
    PixelRegion,
    RedactionAction,
    RedactionAllowlistDecision,
    RedactionFinding,
    RedactionKind,
    RedactionReason,
    RedactionTarget,
    TextSpan,
)
from local_recall.ports.redaction import RedactionRequest

from .detector import DeterministicSecretDetector
from .errors import RedactionFailure, RedactionFailureCode
from .models import SecretMatch

_REPLACEMENT = "[REDACTED]"


@dataclass(frozen=True, slots=True)
class _BlockSlice:
    block: OCRBlock
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class _BlockRedaction:
    start: int
    end: int
    detector_id: str
    kind: RedactionKind
    confidence: SourceConfidence


class DeterministicRedactionPolicy:
    def __init__(
        self,
        settings: RedactionSettings | None = None,
        *,
        detector: DeterministicSecretDetector | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings or RedactionSettings()
        self._detector = detector or DeterministicSecretDetector(
            entropy=self._settings.entropy,
            custom_patterns=self._settings.custom_patterns,
            allowlists=self._settings.allowlists,
        )
        self._now = now or (lambda: datetime.now(UTC))

    @property
    def revision(self) -> str:
        return self._settings.policy_revision

    async def redact(self, request: RedactionRequest) -> RedactedRecord:
        frame = request.frame
        record_id = frame.frame_id
        if request.ocr.frame_id != frame.frame_id:
            raise RedactionFailure(record_id, RedactionFailureCode.FRAME_MISMATCH)
        if request.policy_revision != self.revision:
            raise RedactionFailure(record_id, RedactionFailureCode.POLICY_FAILURE)
        if (
            not self._settings.enabled
            or not self._settings.deterministic_required
            or not self._settings.fail_on_uncertain
        ):
            raise RedactionFailure(record_id, RedactionFailureCode.POLICY_FAILURE)
        try:
            _validate_ocr_regions(frame.width, frame.height, request.ocr.blocks, record_id)
            document, slices = _ocr_document(request.ocr.blocks)
            detection = self._detector.scan(document)
            block_redactions: dict[UUID, list[_BlockRedaction]] = {
                item.block.block_id: [] for item in slices
            }
            findings: list[RedactionFinding] = []
            allowlist_decisions: list[RedactionAllowlistDecision] = []

            for match in detection.matches:
                self._apply_document_match(match, slices, block_redactions, findings)
            for item in detection.allowlisted:
                allowlist_decisions.append(
                    RedactionAllowlistDecision(
                        decision_id=uuid4(),
                        detector_id=item.detector_id,
                        allowlist_id=item.allowlist_id,
                        target=RedactionTarget.OCR_TEXT,
                        value_digest=item.value_digest,
                    )
                )

            for item in slices:
                block = item.block
                if block.text and block.confidence.value < self._settings.low_confidence_threshold:
                    redaction = _BlockRedaction(
                        start=0,
                        end=len(block.text),
                        detector_id="low-confidence-ocr",
                        kind=RedactionKind.POLICY,
                        confidence=block.confidence,
                    )
                    block_redactions[block.block_id].append(redaction)
                    findings.extend(_findings_for_block(block, redaction))

            redacted_metadata, metadata_findings, metadata_allowlists = self._redact_metadata(
                frame.metadata
            )
            findings.extend(metadata_findings)
            allowlist_decisions.extend(metadata_allowlists)

            regions: list[PixelRegion] = []
            redacted_text: list[str] = []
            for item in slices:
                block = item.block
                spans = block_redactions[block.block_id]
                redacted_text.append(_replace_spans(block.text, spans))
                if spans:
                    regions.append(block.region)

            redacted_pixels = _mask_regions(frame, regions)
            redacted_frame = RedactedFrame(
                frame_id=frame.frame_id,
                generation=frame.generation,
                captured_at=frame.captured_at,
                width=frame.width,
                height=frame.height,
                stride=frame.stride,
                pixel_format=frame.pixel_format,
                pixels=redacted_pixels,
                metadata=redacted_metadata,
                ocr_text=tuple(redacted_text),
                findings=tuple(findings),
                policy_revision=self.revision,
                allowlist_decisions=tuple(allowlist_decisions),
            )
            return RedactedRecord(
                record_id=record_id,
                frame=redacted_frame,
                created_at=self._now(),
            )
        except RedactionFailure:
            raise
        except Exception as exc:
            raise RedactionFailure(record_id, RedactionFailureCode.POLICY_FAILURE) from exc

    def _apply_document_match(
        self,
        match: SecretMatch,
        slices: tuple[_BlockSlice, ...],
        block_redactions: dict[UUID, list[_BlockRedaction]],
        findings: list[RedactionFinding],
    ) -> None:
        for item in slices:
            overlap_start = max(match.start, item.start)
            overlap_end = min(match.end, item.end)
            if overlap_start >= overlap_end:
                continue
            local = _BlockRedaction(
                start=overlap_start - item.start,
                end=overlap_end - item.start,
                detector_id=match.detector_id,
                kind=match.kind,
                confidence=match.confidence,
            )
            block_redactions[item.block.block_id].append(local)
            findings.extend(_findings_for_block(item.block, local))

    def _redact_metadata(
        self, metadata: ContextMetadata
    ) -> tuple[
        ContextMetadata,
        list[RedactionFinding],
        list[RedactionAllowlistDecision],
    ]:
        retained: list[ContextField] = []
        findings: list[RedactionFinding] = []
        decisions: list[RedactionAllowlistDecision] = []
        for field in metadata.fields:
            sensitive_name = self._detector.sensitive_metadata_name(field.name)
            detection = self._detector.scan(field.value) if isinstance(field.value, str) else None
            field_matches = detection.matches if detection is not None else ()
            if sensitive_name is None and not field_matches:
                retained.append(field)
            else:
                if sensitive_name is not None:
                    detector_id, kind = sensitive_name
                    findings.append(_metadata_finding(field.name, detector_id, kind))
                for match in field_matches:
                    findings.append(
                        _metadata_finding(
                            field.name, match.detector_id, match.kind, match.confidence
                        )
                    )
            if detection is not None:
                for item in detection.allowlisted:
                    decisions.append(
                        RedactionAllowlistDecision(
                            decision_id=uuid4(),
                            detector_id=item.detector_id,
                            allowlist_id=item.allowlist_id,
                            target=RedactionTarget.METADATA,
                            value_digest=item.value_digest,
                            metadata_field=field.name,
                        )
                    )
        return ContextMetadata(metadata.observed_at, tuple(retained)), findings, decisions


def _validate_ocr_regions(
    frame_width: int,
    frame_height: int,
    blocks: tuple[OCRBlock, ...],
    record_id: UUID,
) -> None:
    for block in blocks:
        region = block.region
        if region.x + region.width > frame_width or region.y + region.height > frame_height:
            raise RedactionFailure(record_id, RedactionFailureCode.INVALID_REGION)


def _ocr_document(blocks: tuple[OCRBlock, ...]) -> tuple[str, tuple[_BlockSlice, ...]]:
    parts: list[str] = []
    slices: list[_BlockSlice] = []
    offset = 0
    for index, block in enumerate(blocks):
        if index:
            parts.append("\n")
            offset += 1
        start = offset
        parts.append(block.text)
        offset += len(block.text)
        slices.append(_BlockSlice(block, start, offset))
    return "".join(parts), tuple(slices)


def _findings_for_block(
    block: OCRBlock, redaction: _BlockRedaction
) -> tuple[RedactionFinding, ...]:
    reason = (
        RedactionReason.POLICY_RULE
        if redaction.kind is RedactionKind.POLICY
        else RedactionReason.DETERMINISTIC_DETECTOR
    )
    return (
        RedactionFinding(
            finding_id=uuid4(),
            target=RedactionTarget.OCR_TEXT,
            kind=redaction.kind,
            reason=reason,
            action=RedactionAction.REPLACE_TEXT,
            detector_id=redaction.detector_id,
            confidence=redaction.confidence,
            text_span=TextSpan(redaction.start, redaction.end),
        ),
        RedactionFinding(
            finding_id=uuid4(),
            target=RedactionTarget.PIXELS,
            kind=redaction.kind,
            reason=reason,
            action=RedactionAction.MASK_PIXELS,
            detector_id=redaction.detector_id,
            confidence=redaction.confidence,
            pixel_region=block.region,
        ),
    )


def _metadata_finding(
    field_name: str,
    detector_id: str,
    kind: RedactionKind,
    confidence: SourceConfidence | None = None,
) -> RedactionFinding:
    resolved_confidence = confidence or SourceConfidence(1.0)
    return RedactionFinding(
        finding_id=uuid4(),
        target=RedactionTarget.METADATA,
        kind=kind,
        reason=RedactionReason.DETERMINISTIC_DETECTOR,
        action=RedactionAction.DROP_FIELD,
        detector_id=detector_id,
        confidence=resolved_confidence,
        metadata_field=field_name,
    )


def _replace_spans(text: str, redactions: list[_BlockRedaction]) -> str:
    if not redactions:
        return text
    ranges = _merge_ranges((item.start, item.end) for item in redactions)
    parts: list[str] = []
    cursor = 0
    for start, end in ranges:
        parts.append(text[cursor:start])
        parts.append(_REPLACEMENT)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    ordered = sorted(ranges)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return tuple(merged)


def _mask_regions(frame: object, regions: list[PixelRegion]) -> bytes:
    from local_recall.domain.frames import PixelFormat, RawFrame

    if not isinstance(frame, RawFrame):
        raise TypeError("frame must be a RawFrame")
    pixels = bytearray(frame.pixels)
    unique = {(region.x, region.y, region.width, region.height) for region in regions}
    for x, y, width, height in unique:
        if x + width > frame.width or y + height > frame.height:
            raise RedactionFailure(frame.frame_id, RedactionFailureCode.INVALID_REGION)
        for row in range(y, y + height):
            for column in range(x, x + width):
                offset = row * frame.stride + column * frame.pixel_format.bytes_per_pixel
                if frame.pixel_format is PixelFormat.RGBA8:
                    pixels[offset : offset + 4] = b"\x00\x00\x00\xff"
                elif frame.pixel_format is PixelFormat.RGB8:
                    pixels[offset : offset + 3] = b"\x00\x00\x00"
                else:
                    pixels[offset] = 0
    return bytes(pixels)
