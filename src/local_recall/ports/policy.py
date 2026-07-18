from __future__ import annotations

from typing import Protocol, runtime_checkable

from local_recall.domain.capture import CaptureDecision, CapturePolicyInput


@runtime_checkable
class CapturePolicy(Protocol):
    @property
    def revision(self) -> str: ...

    async def evaluate(self, request: CapturePolicyInput) -> CaptureDecision: ...
