from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.crypto import (
    EncryptionFailure,
    EncryptionFailureCode,
    EnvelopeCipher,
    EnvelopeEncryptionStageProcessor,
    KeyProviderRegistry,
    OSKeyringProvider,
    decode_encrypted_stage,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline.cancellation import PipelineCancellationToken
from local_recall.pipeline.models import RedactedStageItem


class MemoryBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 18, 12, 0, tzinfo=UTC)

    def monotonic_ns(self) -> int:
        return 100


def redacted_item() -> RedactedStageItem:
    return RedactedStageItem(
        record_id=uuid4(),
        generation=CaptureGeneration(3),
        configuration_revision="config-v3",
        deadline_monotonic_ns=1000,
        frames=(b"redacted-header", b"masked-pixels"),
    )


def test_redacted_stage_encrypts_before_persistence_boundary() -> None:
    provider = OSKeyringProvider(MemoryBackend())
    processor = EnvelopeEncryptionStageProcessor(
        KeyProviderRegistry((provider,)),
        primary_provider_id=provider.provider_id,
        clock=FixedClock(),
    )
    item = redacted_item()
    token = PipelineCancellationToken(item.generation, threading.Event())

    encrypted_item = processor.process(item, token)
    envelope = decode_encrypted_stage(encrypted_item)
    frames = asyncio.run(EnvelopeCipher().decrypt_frames(envelope, provider))

    assert frames == item.frames
    assert item.frames[0] not in encrypted_item.frames
    assert item.frames[1] not in encrypted_item.frames


def test_cancelled_stage_never_creates_a_key_or_envelope() -> None:
    backend = MemoryBackend()
    provider = OSKeyringProvider(backend)
    processor = EnvelopeEncryptionStageProcessor(
        KeyProviderRegistry((provider,)),
        primary_provider_id=provider.provider_id,
        clock=FixedClock(),
    )
    item = redacted_item()
    event = threading.Event()
    event.set()

    with pytest.raises(EncryptionFailure) as captured:
        processor.process(item, PipelineCancellationToken(item.generation, event))

    assert captured.value.code is EncryptionFailureCode.CANCELLED
    assert backend.values == {}


def test_missing_key_provider_fails_closed_before_encrypted_output() -> None:
    item = redacted_item()
    processor = EnvelopeEncryptionStageProcessor(
        KeyProviderRegistry(()),
        primary_provider_id="not-configured",
        clock=FixedClock(),
    )

    with pytest.raises(EncryptionFailure) as captured:
        processor.process(
            item,
            PipelineCancellationToken(item.generation, threading.Event()),
        )

    assert captured.value.code is EncryptionFailureCode.KEY_UNAVAILABLE
    assert "not-configured" not in str(captured.value)
