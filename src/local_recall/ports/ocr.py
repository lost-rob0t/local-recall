from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from local_recall.domain.frames import OCRResult, RawFrame


@dataclass(frozen=True, slots=True)
class OCRRequest:
    frame: RawFrame
    language_hints: tuple[str, ...] = ()


@runtime_checkable
class OCRProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    async def recognize(self, request: OCRRequest) -> OCRResult: ...
