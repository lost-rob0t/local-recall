from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import replace
from datetime import datetime
from uuid import UUID

from nacl.exceptions import CryptoError

from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyHandle,
    KeyPurpose,
    KeyRequest,
    SecretKeyMaterial,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.ports.keys import KeyProvider, KeyUnwrapRequest, KeyWrapRequest

from .bindings import KEY_BYTES, NONCE_BYTES, decrypt, encrypt
from .errors import (
    EncryptionFailure,
    EncryptionFailureCode,
    KeyProviderFailure,
)

ENVELOPE_SCHEMA_VERSION = 1
ENVELOPE_ALGORITHM = "xchacha20-poly1305-ietf"


class EnvelopeCipher:
    async def encrypt_frames(
        self,
        *,
        record_id: UUID,
        generation: CaptureGeneration,
        configuration_revision: str,
        frames: tuple[bytes, ...],
        provider: KeyProvider,
        created_at: datetime,
    ) -> EncryptedRecordEnvelope:
        frame_sizes = tuple(len(frame) for frame in frames)
        if not frame_sizes or any(size <= 0 for size in frame_sizes):
            raise EncryptionFailure(record_id, EncryptionFailureCode.CODEC_FAILURE)

        aad = _associated_data(
            record_id=record_id,
            generation=generation,
            configuration_revision=configuration_revision,
            schema_version=ENVELOPE_SCHEMA_VERSION,
            algorithm=ENVELOPE_ALGORITHM,
            frame_sizes=frame_sizes,
            created_at=created_at,
        )
        aad_digest = hashlib.sha256(aad).digest()
        plaintext = bytearray().join(frames)
        try:
            key_handle, wrapped_data_key, nonce, ciphertext = await _encrypt_payload(
                bytes(plaintext),
                aad,
                aad_digest,
                provider,
            )
        except KeyProviderFailure as exc:
            raise EncryptionFailure(record_id, EncryptionFailureCode.KEY_UNAVAILABLE) from exc
        finally:
            plaintext[:] = b"\x00" * len(plaintext)

        return EncryptedRecordEnvelope(
            record_id=record_id,
            generation=generation,
            configuration_revision=configuration_revision,
            schema_version=ENVELOPE_SCHEMA_VERSION,
            algorithm=ENVELOPE_ALGORITHM,
            key=key_handle,
            plaintext_frame_sizes=frame_sizes,
            wrapped_data_key=wrapped_data_key,
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data_digest=aad_digest,
            created_at=created_at,
        )

    async def decrypt_frames(
        self,
        envelope: EncryptedRecordEnvelope,
        provider: KeyProvider,
    ) -> tuple[bytes, ...]:
        aad_digest = _validated_associated_data_digest(envelope)
        aad = _associated_data_from_envelope(envelope)
        try:
            data_key = await provider.unwrap_data_key(
                KeyUnwrapRequest(
                    key=envelope.key,
                    wrapped_data_key=envelope.wrapped_data_key,
                    associated_data=_wrap_associated_data(aad_digest),
                )
            )
            with data_key:
                plaintext = decrypt(
                    envelope.ciphertext,
                    aad,
                    envelope.nonce,
                    data_key.copy_bytes(),
                )
        except (CryptoError, KeyProviderFailure) as exc:
            raise EncryptionFailure(
                envelope.record_id, EncryptionFailureCode.AUTHENTICATION_FAILED
            ) from exc

        plaintext_buffer = bytearray(plaintext)
        try:
            return _split_frames(plaintext_buffer, envelope.plaintext_frame_sizes)
        except ValueError as exc:
            raise EncryptionFailure(
                envelope.record_id, EncryptionFailureCode.AUTHENTICATION_FAILED
            ) from exc
        finally:
            plaintext_buffer[:] = b"\x00" * len(plaintext_buffer)

    async def rewrap_data_key(
        self,
        envelope: EncryptedRecordEnvelope,
        *,
        current_provider: KeyProvider,
        replacement_provider: KeyProvider,
    ) -> EncryptedRecordEnvelope:
        try:
            aad_digest = _validated_associated_data_digest(envelope)
        except EncryptionFailure as exc:
            raise EncryptionFailure(
                envelope.record_id, EncryptionFailureCode.REWRAP_FAILED
            ) from exc
        wrap_aad = _wrap_associated_data(aad_digest)
        try:
            data_key = await current_provider.unwrap_data_key(
                KeyUnwrapRequest(
                    key=envelope.key,
                    wrapped_data_key=envelope.wrapped_data_key,
                    associated_data=wrap_aad,
                )
            )
            with data_key:
                replacement_key = await replacement_provider.active_key(
                    KeyRequest(KeyPurpose.RECORD, create_if_missing=True)
                )
                wrapped = await replacement_provider.wrap_data_key(
                    KeyWrapRequest(
                        key=replacement_key,
                        material=data_key,
                        associated_data=wrap_aad,
                    )
                )
        except KeyProviderFailure as exc:
            raise EncryptionFailure(
                envelope.record_id, EncryptionFailureCode.REWRAP_FAILED
            ) from exc
        return replace(envelope, key=replacement_key, wrapped_data_key=wrapped)


async def _encrypt_payload(
    plaintext: bytes,
    aad: bytes,
    aad_digest: bytes,
    provider: KeyProvider,
) -> tuple[KeyHandle, bytes, bytes, bytes]:
    key_handle = await provider.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True))
    with SecretKeyMaterial.random(KEY_BYTES) as data_key:
        wrapped_data_key = await provider.wrap_data_key(
            KeyWrapRequest(
                key=key_handle,
                material=data_key,
                associated_data=_wrap_associated_data(aad_digest),
            )
        )
        nonce = secrets.token_bytes(NONCE_BYTES)
        ciphertext = encrypt(
            plaintext,
            aad,
            nonce,
            data_key.copy_bytes(),
        )
    return key_handle, wrapped_data_key, nonce, ciphertext


def _validated_associated_data_digest(envelope: EncryptedRecordEnvelope) -> bytes:
    if (
        envelope.schema_version != ENVELOPE_SCHEMA_VERSION
        or envelope.algorithm != ENVELOPE_ALGORITHM
    ):
        raise EncryptionFailure(envelope.record_id, EncryptionFailureCode.AUTHENTICATION_FAILED)
    aad_digest = hashlib.sha256(_associated_data_from_envelope(envelope)).digest()
    if not secrets.compare_digest(aad_digest, envelope.associated_data_digest):
        raise EncryptionFailure(envelope.record_id, EncryptionFailureCode.AUTHENTICATION_FAILED)
    return aad_digest


def _associated_data_from_envelope(envelope: EncryptedRecordEnvelope) -> bytes:
    return _associated_data(
        record_id=envelope.record_id,
        generation=envelope.generation,
        configuration_revision=envelope.configuration_revision,
        schema_version=envelope.schema_version,
        algorithm=envelope.algorithm,
        frame_sizes=envelope.plaintext_frame_sizes,
        created_at=envelope.created_at,
    )


def _associated_data(
    *,
    record_id: UUID,
    generation: CaptureGeneration,
    configuration_revision: str,
    schema_version: int,
    algorithm: str,
    frame_sizes: tuple[int, ...],
    created_at: datetime,
) -> bytes:
    value = {
        "algorithm": algorithm,
        "configuration_revision": configuration_revision,
        "created_at": created_at.isoformat(),
        "frame_sizes": frame_sizes,
        "generation": generation.value,
        "record_id": str(record_id),
        "schema_version": schema_version,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _wrap_associated_data(aad_digest: bytes) -> bytes:
    return b"local-recall-key-wrap-v1\x00" + aad_digest


def _split_frames(
    plaintext: bytes | bytearray,
    frame_sizes: tuple[int, ...],
) -> tuple[bytes, ...]:
    if sum(frame_sizes) != len(plaintext):
        raise ValueError("plaintext size does not match authenticated frame sizes")
    frames: list[bytes] = []
    offset = 0
    for size in frame_sizes:
        frames.append(bytes(plaintext[offset : offset + size]))
        offset += size
    return tuple(frames)
