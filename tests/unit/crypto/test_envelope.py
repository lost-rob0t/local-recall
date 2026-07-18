from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.crypto import (
    EncryptionFailure,
    EncryptionFailureCode,
    EnvelopeCipher,
    OSKeyringProvider,
    decode_encrypted_stage,
    encode_encrypted_stage,
)
from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyPurpose,
    KeyRequest,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline.models import RedactedStageItem
from local_recall.ports.keys import KeyRotationRequest


class MemoryKeyringBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def encrypt_fixture(
    provider: OSKeyringProvider,
) -> tuple[EnvelopeCipher, RedactedStageItem, EncryptedRecordEnvelope]:
    cipher = EnvelopeCipher()
    item = RedactedStageItem(
        record_id=uuid4(),
        generation=CaptureGeneration(7),
        configuration_revision="config-v7",
        deadline_monotonic_ns=100,
        frames=(b"synthetic-header", b"redacted-pixels"),
    )
    envelope = asyncio.run(
        cipher.encrypt_frames(
            record_id=item.record_id,
            generation=item.generation,
            configuration_revision=item.configuration_revision,
            frames=item.frames,
            provider=provider,
            created_at=datetime.now(UTC),
        )
    )
    return cipher, item, envelope


def test_authenticated_envelope_round_trip() -> None:
    provider = OSKeyringProvider(MemoryKeyringBackend())
    cipher, item, envelope = encrypt_fixture(provider)

    frames = asyncio.run(cipher.decrypt_frames(envelope, provider))

    assert frames == item.frames
    assert b"synthetic-header" not in envelope.ciphertext
    assert b"redacted-pixels" not in envelope.ciphertext


def test_ciphertext_tampering_fails_authentication_cleanly() -> None:
    provider = OSKeyringProvider(MemoryKeyringBackend())
    cipher, _, envelope = encrypt_fixture(provider)
    tampered = replace(
        envelope,
        ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]),
    )

    with pytest.raises(EncryptionFailure) as captured:
        asyncio.run(cipher.decrypt_frames(tampered, provider))

    assert captured.value.code is EncryptionFailureCode.AUTHENTICATION_FAILED
    assert "ciphertext" not in str(captured.value)


def test_authenticated_metadata_tampering_is_rejected() -> None:
    provider = OSKeyringProvider(MemoryKeyringBackend())
    cipher, _, envelope = encrypt_fixture(provider)
    tampered = replace(envelope, configuration_revision="other-config")

    with pytest.raises(EncryptionFailure) as captured:
        asyncio.run(cipher.decrypt_frames(tampered, provider))

    assert captured.value.code is EncryptionFailureCode.AUTHENTICATION_FAILED


def test_wrong_master_key_fails_authentication() -> None:
    first = OSKeyringProvider(MemoryKeyringBackend())
    second = OSKeyringProvider(MemoryKeyringBackend())
    cipher, _, envelope = encrypt_fixture(first)
    asyncio.run(
        second.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True))
    )

    with pytest.raises(EncryptionFailure) as captured:
        asyncio.run(cipher.decrypt_frames(envelope, second))

    assert captured.value.code is EncryptionFailureCode.AUTHENTICATION_FAILED


def test_rotation_rewraps_data_key_without_changing_ciphertext() -> None:
    provider = OSKeyringProvider(MemoryKeyringBackend())
    cipher, item, envelope = encrypt_fixture(provider)
    rotated = asyncio.run(
        provider.rotate(KeyRotationRequest(envelope.key, "scheduled-rotation"))
    )
    assert rotated.version == envelope.key.version + 1

    rewrapped = asyncio.run(
        cipher.rewrap_data_key(
            envelope,
            current_provider=provider,
            replacement_provider=provider,
        )
    )

    assert rewrapped.ciphertext == envelope.ciphertext
    assert rewrapped.nonce == envelope.nonce
    assert rewrapped.key.version == rotated.version
    assert rewrapped.wrapped_data_key != envelope.wrapped_data_key
    assert asyncio.run(cipher.decrypt_frames(rewrapped, provider)) == item.frames


def test_encrypted_stage_codec_round_trip() -> None:
    provider = OSKeyringProvider(MemoryKeyringBackend())
    _, item, envelope = encrypt_fixture(provider)

    encoded = encode_encrypted_stage(item, envelope)
    decoded = decode_encrypted_stage(encoded)

    assert decoded == envelope
    assert b"redacted-pixels" not in encoded.frames[0]
