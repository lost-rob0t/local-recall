from __future__ import annotations

import re
from dataclasses import dataclass, field

from local_recall.domain.metadata import SourceConfidence
from local_recall.domain.redaction import RedactionKind


@dataclass(frozen=True, slots=True, repr=False)
class SecretMatch:
    detector_id: str
    kind: RedactionKind
    start: int
    end: int
    confidence: SourceConfidence
    matched_text: str = field(repr=False)

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", self.detector_id):
            raise ValueError("detector identifier is invalid")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("secret match span is invalid")
        if len(self.matched_text) != self.end - self.start:
            raise ValueError("secret match text does not match its span")

    def __repr__(self) -> str:
        return (
            f"SecretMatch(detector_id={self.detector_id!r}, kind={self.kind.value!r}, "
            f"start={self.start}, end={self.end}, confidence={self.confidence!r})"
        )


@dataclass(frozen=True, slots=True)
class AllowlistedMatch:
    detector_id: str
    allowlist_id: str
    start: int
    end: int
    value_digest: str


@dataclass(frozen=True, slots=True)
class DetectionResult:
    matches: tuple[SecretMatch, ...]
    allowlisted: tuple[AllowlistedMatch, ...]
