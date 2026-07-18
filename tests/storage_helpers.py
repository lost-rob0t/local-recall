from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from nacl import bindings
from nacl.exceptions import CryptoError

from local_recall.crypto.bindings import KEY_BYTES, NONCE_BYTES, decrypt, encrypt
from local_recall.crypto.errors import KeyProviderFailure, KeyProviderFailureCode
from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyHandle,
    KeyPurpose,
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
    provider_id = "memory-storage"

    def __init__(self) -> None:
        self._handle = KeyHandle("storage-master", self.provider_id, 1)
        self._key = bytes(range(KEY_BYTES))

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        del request
        return KeyHealthReport(self.provider_id, KeyHealthStatus.READY, self._handle)

    async def active_key(self, request: KeyRequest) -> KeyHandle:
        if request.purpose is not KeyPurpose.INDEX:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.INVALID_KEY
            )
        return self._handle

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes:
        if request.key != self._handle:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.INVALID_KEY
            )
        nonce = bytes(range(NONCE_BYTES))
        return nonce + encrypt(
            request.material.copy_bytes(),
            request.associated_data,
            nonce,
            self._key,
        )

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        if request.key != self._handle or len(request.wrapped_data_key) <= NONCE_BYTES:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.INVALID_KEY
            )
        nonce = request.wrapped_data_key[:NONCE_BYTES]
        ciphertext = request.wrapped_data_key[NONCE_BYTES:]
        try:
            plaintext = decrypt(
                ciphertext,
                request.associated_data,
                nonce,
                self._key,
            )
        except CryptoError as exc:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.INVALID_KEY
            ) from exc
        return SecretKeyMaterial.from_bytes(plaintext)

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle:
        del request
        return self._handle

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult:
        return KeyDestructionResult(request.key, False)


def make_envelope(
    *,
    created_at: datetime | None = None,
    marker: bytes = b"synthetic-redacted-record",
) -> EncryptedRecordEnvelope:
    timestamp = created_at or datetime(2026, 7, 18, 12, 34, 56, 123456, tzinfo=UTC)
    record_key = bindings.randombytes(KEY_BYTES)
    nonce = bindings.randombytes(NONCE_BYTES)
    ciphertext = encrypt(marker, b"inner-associated-data", nonce, record_key)
    return EncryptedRecordEnvelope(
        record_id=uuid4(),
        generation=CaptureGeneration(4),
        configuration_revision="synthetic-config-revision",
        schema_version=1,
        algorithm="xchacha20-poly1305-ietf",
        key=KeyHandle("record-key", "memory-record", 1),
        plaintext_frame_sizes=(len(marker),),
        wrapped_data_key=b"synthetic-wrapped-record-key",
        nonce=nonce,
        ciphertext=ciphertext,
        associated_data_digest=b"d" * 32,
        created_at=timestamp,
    )
