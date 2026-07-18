from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from ._validation import require_nonempty
from .metadata import SourceConfidence


class RedactionTarget(StrEnum):
    PIXELS = "pixels"
    OCR_TEXT = "ocr_text"
    METADATA = "metadata"


class RedactionKind(StrEnum):
    API_TOKEN = "api_token"
    PASSWORD = "password"
    USERNAME = "username"
    PRIVATE_KEY = "private_key"
    AUTHORIZATION_HEADER = "authorization_header"
    CONNECTION_STRING = "connection_string"
    HIGH_ENTROPY_SECRET = "high_entropy_secret"
    EMAIL = "email"
    CUSTOM_PATTERN = "custom_pattern"
    POLICY = "policy"


class RedactionReason(StrEnum):
    DETERMINISTIC_DETECTOR = "deterministic_detector"
    MODEL_ASSISTED_DETECTOR = "model_assisted_detector"
    POLICY_RULE = "policy_rule"
    USER_RULE = "user_rule"


class RedactionAction(StrEnum):
    MASK_PIXELS = "mask_pixels"
    REPLACE_TEXT = "replace_text"
    DROP_FIELD = "drop_field"
    REJECT_RECORD = "reject_record"


@dataclass(frozen=True, slots=True)
class TextSpan:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("text span must be a non-empty non-negative range")


@dataclass(frozen=True, slots=True)
class PixelRegion:
    x: int
    y: int
    width: int
    height: int

    def __post_init__(self) -> None:
        if self.x < 0 or self.y < 0:
            raise ValueError("pixel region origin must be non-negative")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("pixel region dimensions must be positive")


@dataclass(frozen=True, slots=True)
class RedactionFinding:
    finding_id: UUID
    target: RedactionTarget
    kind: RedactionKind
    reason: RedactionReason
    action: RedactionAction
    detector_id: str
    confidence: SourceConfidence
    text_span: TextSpan | None = None
    pixel_region: PixelRegion | None = None
    metadata_field: str | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.detector_id, "detector_id")
        if self.target is RedactionTarget.OCR_TEXT:
            if (
                self.text_span is None
                or self.pixel_region is not None
                or self.metadata_field is not None
            ):
                raise ValueError("OCR text findings require exactly one text span")
        elif self.target is RedactionTarget.PIXELS:
            if (
                self.pixel_region is None
                or self.text_span is not None
                or self.metadata_field is not None
            ):
                raise ValueError("pixel findings require exactly one pixel region")
        elif self.target is RedactionTarget.METADATA:
            if (
                self.metadata_field is None
                or self.text_span is not None
                or self.pixel_region is not None
            ):
                raise ValueError("metadata findings require exactly one metadata field")
            require_nonempty(self.metadata_field, "metadata_field")
