from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from uuid import UUID

from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyHandle,
    KeyRequest,
    SecretKeyMaterial,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.ports.keys import (
    KeyDestructionRequest,
    KeyDestructionResult,
    KeyHealthReport,
    KeyHealthStatus,
    KeyRotationRequest,
    KeyUnwrapRequest,
    KeyWrapRequest,
)


class MemoryKeyProvider:
    def __init__(self, master_key: bytes = b"K" * 32) -> None:
        self._master_key = master_key
        self._handle = KeyHandle(
            key_id="memory-index-key",
            provider_id=self.provider_id,
            version=1,
        )

    @property
    def provider_id(self) -> str:
        return "memory-test"

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        del request
        return KeyHealthReport(self.provider_id, KeyHealthStatus.READY, self._handle)

    async def active_key(self, request: KeyRequest) -> KeyHandle:
        del request
        return self._handle

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes:
        material = request.material.copy_bytes()
        stream = _expand(self._master_key, len(material))
        wrapped = bytes(
            left ^ right for left, right in zip(material, stream, strict=True)
        )
        tag = hmac.new(
            self._master_key,
            request.associated_data + material,
            hashlib.sha256,
        ).digest()
        return wrapped + tag

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        if len(request.wrapped_data_key) < 33:
            raise ValueError("invalid wrapped key")
        wrapped = request.wrapped_data_key[:-32]
        tag = request.wrapped_data_key[-32:]
        stream = _expand(self._master_key, len(wrapped))
        material = bytes(
            left ^ right for left, right in zip(wrapped, stream, strict=True)
        )
        expected = hmac.new(
            self._master_key,
            request.associated_data + material,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("invalid wrapped key")
        return SecretKeyMaterial.from_bytes(material)

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle:
        del request
        return self._handle

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult:
        return KeyDestructionResult(request.key, destroyed=False)


def make_envelope(
    *,
    record_id: UUID = UUID("2eb1204a-6c45-4da5-a7fb-88fa0c10a111"),
    created_at: datetime = datetime(2026, 7, 18, 12, 34, 56, 123456, tzinfo=UTC),
) -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=record_id,
        generation=CaptureGeneration(7),
        configuration_revision="seeded-window-title-do-not-persist",
        schema_version=1,
        algorithm="xchacha20-poly1305-ietf",
        key=KeyHandle(key_id="record-key", provider_id="memory-test", version=3),
        plaintext_frame_sizes=(17, 19),
        wrapped_data_key=b"wrapped-record-key-material" * 2,
        nonce=b"N" * 24,
        ciphertext=b"seeded-screenshot-and-ocr-content-must-remain-hidden",
        associated_data_digest=b"D" * 32,
        created_at=created_at,
    )


def _expand(key: bytes, size: int) -> bytes:
    repeats = (size + len(key) - 1) // len(key)
    return (key * repeats)[:size]
