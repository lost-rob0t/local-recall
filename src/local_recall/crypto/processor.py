from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from local_recall.domain.crypto import KeyPurpose, KeyRequest
from local_recall.pipeline.cancellation import PipelineCancellationToken
from local_recall.pipeline.models import EncryptedStageItem, RedactedStageItem
from local_recall.ports.clock import Clock

from .codec import encode_encrypted_stage
from .envelope import EnvelopeCipher
from .errors import EncryptionFailure, EncryptionFailureCode
from .registry import KeyProviderRegistry


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ns(self) -> int:
        import time

        return time.monotonic_ns()


class EnvelopeEncryptionStageProcessor:
    def __init__(
        self,
        registry: KeyProviderRegistry,
        *,
        primary_provider_id: str,
        explicit_fallback_provider_id: str | None = None,
        cipher: EnvelopeCipher | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._registry = registry
        self._primary_provider_id = primary_provider_id
        self._explicit_fallback_provider_id = explicit_fallback_provider_id
        self._cipher = cipher or EnvelopeCipher()
        self._clock = clock or _SystemClock()

    def process(
        self,
        item: RedactedStageItem,
        cancellation: PipelineCancellationToken,
    ) -> EncryptedStageItem:
        if cancellation.cancelled:
            raise EncryptionFailure(item.record_id, EncryptionFailureCode.CANCELLED)
        selection = asyncio.run(
            self._registry.select(
                self._primary_provider_id,
                KeyRequest(KeyPurpose.RECORD, create_if_missing=True),
                explicit_fallback_provider_id=self._explicit_fallback_provider_id,
            )
        )
        envelope = asyncio.run(
            self._cipher.encrypt_frames(
                record_id=item.record_id,
                generation=item.generation,
                configuration_revision=item.configuration_revision,
                frames=item.frames,
                provider=selection.provider,
                created_at=self._clock.now(),
            )
        )
        if cancellation.cancelled:
            raise EncryptionFailure(item.record_id, EncryptionFailureCode.CANCELLED)
        return encode_encrypted_stage(item, envelope)
