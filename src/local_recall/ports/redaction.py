from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from local_recall.domain.frames import OCRResult, RawFrame, RedactedRecord


@dataclass(frozen=True, slots=True)
class RedactionRequest:
    frame: RawFrame
    ocr: OCRResult
    policy_revision: str


@runtime_checkable
class RedactionPolicy(Protocol):
    @property
    def revision(self) -> str: ...

    async def redact(self, request: RedactionRequest) -> RedactedRecord: ...
