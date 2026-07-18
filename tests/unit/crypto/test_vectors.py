from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from local_recall.config.models import CredentialReference, EncryptionSettings
from local_recall.crypto import CryptoError, InMemoryKeyProvider, KeyProviderRouter, RecordCipher
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline.models import RedactedStageItem


def _settings() -> EncryptionSettings:
    return EncryptionSettings(
        provider_id="memory",
        key_reference=CredentialReference(provider_id="memory", reference="records"),
    )


def _source() -> RedactedStageItem:
    return RedactedStageItem(
        record_id=UUID("00000000-0000-0000-0000-000000000123"),
        generation=CaptureGeneration(7),
        configuration_revision="config-revision-1",
        deadline_monotonic_ns=10**18,
        frames=(b"abc", b"de"),
    )


def _fixed_random(length: int) -> bytes:
    if length == 32:
        return b"\x01" * length
    if length == 24:
        return b"\x02" * length
    raise AssertionError("unexpected random request")


def test_xchacha20_poly1305_known_answer_vector() -> None:
    fixed_time = datetime(2026, 7, 18, tzinfo=UTC)
    cipher = RecordCipher(
        KeyProviderRouter((InMemoryKeyProvider(),)),
        _settings(),
        random_source=_fixed_random,
        clock=lambda: fixed_time,
    )

    envelope = cipher.encrypt(_source())
    expected_ciphertext = bytes.fromhex(
        "".join(
            (
                "ad04558b",
                "cf109adf",
                "f1dcbcde",
                "6254f004",
                "5d90f114",
                "66",
            )
        )
    )
    expected_digest = bytes.fromhex(
        "".join(
            (
                "222573fc",
                "0058d9f6",
                "77d638c9",
                "7990ed91",
                "04e5ba90",
                "7d07a0c4",
                "6edd586d",
                "02b47d36",
            )
        )
    )

    assert envelope.nonce == b"\x02" * 24
    assert envelope.ciphertext == expected_ciphertext
    assert envelope.associated_data_digest == expected_digest
    assert cipher.decrypt(envelope).frames == (b"abc", b"de")


def test_duplicate_nonce_source_fails_before_reuse() -> None:
    cipher = RecordCipher(
        KeyProviderRouter((InMemoryKeyProvider(),)),
        _settings(),
        random_source=_fixed_random,
        clock=lambda: datetime(2026, 7, 18, tzinfo=UTC),
    )

    cipher.encrypt(_source())
    with pytest.raises(CryptoError, match="nonce_generation_failed"):
        cipher.encrypt(_source())
