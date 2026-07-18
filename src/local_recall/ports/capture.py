from __future__ import annotations

from typing import Protocol, runtime_checkable

from local_recall.domain.capture import ApprovedCaptureRequest
from local_recall.domain.frames import RawFrame


@runtime_checkable
class CaptureBackend(Protocol):
    @property
    def backend_id(self) -> str: ...

    async def capture(self, request: ApprovedCaptureRequest) -> RawFrame: ...
