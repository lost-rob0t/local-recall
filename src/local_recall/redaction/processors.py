from __future__ import annotations

import asyncio

from local_recall.pipeline.cancellation import PipelineCancellationToken
from local_recall.pipeline.models import AnalyzedStageItem, RawStageItem, RedactedStageItem
from local_recall.ports.ocr import OCRProvider, OCRRequest
from local_recall.ports.redaction import RedactionPolicy, RedactionRequest

from .codec import (
    decode_analyzed_stage,
    decode_raw_stage,
    encode_analyzed_stage,
    encode_redacted_stage,
)


class LocalOCRStageProcessor:
    def __init__(
        self,
        provider: OCRProvider,
        *,
        language_hints: tuple[str, ...] = (),
    ) -> None:
        self._provider = provider
        self._language_hints = language_hints

    def process(
        self, item: RawStageItem, cancellation: PipelineCancellationToken
    ) -> AnalyzedStageItem:
        del cancellation
        frame = decode_raw_stage(item)
        result = asyncio.run(
            self._provider.recognize(OCRRequest(frame=frame, language_hints=self._language_hints))
        )
        return encode_analyzed_stage(item, frame, result)


class PrePersistenceRedactionStageProcessor:
    def __init__(self, policy: RedactionPolicy) -> None:
        self._policy = policy

    def process(
        self, item: AnalyzedStageItem, cancellation: PipelineCancellationToken
    ) -> RedactedStageItem:
        del cancellation
        analyzed = decode_analyzed_stage(item)
        record = asyncio.run(
            self._policy.redact(
                RedactionRequest(
                    frame=analyzed.frame,
                    ocr=analyzed.ocr,
                    policy_revision=self._policy.revision,
                )
            )
        )
        return encode_redacted_stage(item, record)
