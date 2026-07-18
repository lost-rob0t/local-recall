from __future__ import annotations

from typing import Protocol, runtime_checkable

from .cancellation import PipelineCancellationToken
from .models import (
    AnalyzedStageItem,
    EncryptedStageItem,
    PipelineFaultEvent,
    RawStageItem,
    RedactedStageItem,
)


@runtime_checkable
class RawStageProcessor(Protocol):
    def process(
        self, item: RawStageItem, cancellation: PipelineCancellationToken
    ) -> AnalyzedStageItem: ...


@runtime_checkable
class AnalysisStageProcessor(Protocol):
    def process(
        self, item: AnalyzedStageItem, cancellation: PipelineCancellationToken
    ) -> RedactedStageItem: ...


@runtime_checkable
class RedactionStageProcessor(Protocol):
    def process(
        self, item: RedactedStageItem, cancellation: PipelineCancellationToken
    ) -> EncryptedStageItem: ...


@runtime_checkable
class EncryptedStageSink(Protocol):
    def persist(
        self, item: EncryptedStageItem, cancellation: PipelineCancellationToken
    ) -> None: ...


@runtime_checkable
class PipelineFaultSink(Protocol):
    def emit(self, event: PipelineFaultEvent) -> None: ...
