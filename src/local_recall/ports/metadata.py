from __future__ import annotations

from typing import Protocol, runtime_checkable

from local_recall.domain.capture import MetadataRequest
from local_recall.domain.metadata import ContextMetadata


@runtime_checkable
class MetadataSource(Protocol):
    @property
    def source_id(self) -> str: ...

    async def collect(self, request: MetadataRequest) -> ContextMetadata: ...
