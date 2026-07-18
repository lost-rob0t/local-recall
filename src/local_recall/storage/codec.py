from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from nacl.exceptions import CryptoError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from local_recall.crypto.bindings import KEY_BYTES, NONCE_BYTES, TAG_BYTES, decrypt, encrypt
from local_recall.domain.crypto import (
    EncryptedRecordEnvelope,
    KeyHandle,
    KeyPurpose,
    KeyRequest,
    SecretKeyMaterial,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.ports.keys import KeyProvider, KeyUnwrapRequest, KeyWrapRequest

from .errors import StorageFailure, StorageFailureCode

CURRENT_STORAGE_SCHEMA_VERSION = 2
_MIN_STORAGE_SCHEMA_VERSION = 1
_OUTER_FORMAT_VERSION = 1
_OUTER_ALGORITHM = "xchacha20-poly1305-ietf"
_PAYLOAD_FORMAT = "encrypted-record-envelope-json-v1"
_MAGIC = b"LRBLOB01"
_HEADER_SIZE_BYTES = 4
_MAX_HEADER_BYTES = 16 * 1024
_MAX_BLOB_BYTES = 512 * 1024 * 1024


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)


class _BlobHeader(_FrozenModel):
    format_version: int = Field(gt=0)
    storage_schema_version: int = Field(gt=0)
    record_id: UUID
    algorithm: str = Field(min_length=1)
    payload_format: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    key_provider_id: str = Field(min_length=1)
    key_version: int = Field(gt=0)
    wrapped_key_size: int = Field(gt=0)
    nonce_size: int = Field(gt=0)
    ciphertext_size: int = Field(gt=0)


class _EnvelopePayload(_FrozenModel):
    record_id: UUID
    generation: int = Field(gt=0)
    configuration_revision: str = Field(min_length=1)
    envelope_schema_version: int = Field(gt=0)
    algorithm: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    key_provider_id: str = Field(min_length=1)
    key_version: int = Field(gt=0)
    plaintext_frame_sizes: tuple[int, ...]
    wrapped_data_key: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ciphertext: str = Field(min_length=1)
    associated_data_digest: str = Field(min_length=1)
    created_at: datetime


@dataclass(frozen=True, slots=True)
class DecodedStoredRecord:
    envelope: EncryptedRecordEnvelope
    storage_schema_version: int
    requires_migration: bool


class EncryptedBlobCodec:
    def __init__(self, key_provider: KeyProvider) -> None:
        self._key_provider = key_provider

    async def encode(
        self,
        envelope: EncryptedRecordEnvelope,
        *,
        storage_schema_version: int = CURRENT_STORAGE_SCHEMA_VERSION,
    ) -> bytes:
        if not isinstance(envelope, EncryptedRecordEnvelope):
            raise TypeError("storage codec accepts EncryptedRecordEnvelope only")
        if not _MIN_STORAGE_SCHEMA_VERSION <= storage_schema_version <= CURRENT_STORAGE_SCHEMA_VERSION:
            raise StorageFailure(envelope.record_id, StorageFailureCode.UNSUPPORTED_SCHEMA)

        payload = _serialize_envelope(envelope)
        key = await self._key_provider.active_key(
            KeyRequest(KeyPurpose.INDEX, create_if_missing=True)
        )
        wrap_aad = _wrap_associated_data(envelope.record_id, storage_schema_version)
        with SecretKeyMaterial.random(KEY_BYTES) as data_key:
            wrapped_data_key = await self._key_provider.wrap_data_key(
                KeyWrapRequest(
                    key=key,
                    material=data_key,
                    associated_data=wrap_aad,
                )
            )
            nonce = secrets.token_bytes(NONCE_BYTES)
            header = _BlobHeader(
                format_version=_OUTER_FORMAT_VERSION,
                storage_schema_version=storage_schema_version,
                record_id=envelope.record_id,
                algorithm=_OUTER_ALGORITHM,
                payload_format=_PAYLOAD_FORMAT,
                key_id=key.key_id,
                key_provider_id=key.provider_id,
                key_version=key.version,
                wrapped_key_size=len(wrapped_data_key),
                nonce_size=len(nonce),
                ciphertext_size=len(payload) + TAG_BYTES,
            )
            header_bytes = _canonical_model_bytes(header)
            if len(header_bytes) > _MAX_HEADER_BYTES:
                raise StorageFailure(envelope.record_id, StorageFailureCode.UNSUPPORTED_SCHEMA)
            prefix = _MAGIC + len(header_bytes).to_bytes(_HEADER_SIZE_BYTES, "big") + header_bytes
            ciphertext = encrypt(payload, prefix, nonce, data_key.copy_bytes())

        blob = prefix + wrapped_data_key + nonce + ciphertext
        if len(blob) > _MAX_BLOB_BYTES:
            raise StorageFailure(envelope.record_id, StorageFailureCode.QUOTA_EXCEEDED)
        return blob

    async def decode(
        self,
        blob: bytes,
        *,
        expected_record_id: UUID,
    ) -> DecodedStoredRecord:
        try:
            header, prefix, wrapped_data_key, nonce, ciphertext = _split_blob(blob)
            if header.record_id != expected_record_id:
                raise StorageFailure(expected_record_id, StorageFailureCode.CORRUPT_RECORD)
            if header.storage_schema_version > CURRENT_STORAGE_SCHEMA_VERSION:
                raise StorageFailure(expected_record_id, StorageFailureCode.UNSUPPORTED_SCHEMA)
            if header.storage_schema_version < _MIN_STORAGE_SCHEMA_VERSION:
                raise StorageFailure(expected_record_id, StorageFailureCode.UNSUPPORTED_SCHEMA)
            key = KeyHandle(
                key_id=header.key_id,
                provider_id=header.key_provider_id,
                version=header.key_version,
            )
            data_key = await self._key_provider.unwrap_data_key(
                KeyUnwrapRequest(
                    key=key,
                    wrapped_data_key=wrapped_data_key,
                    associated_data=_wrap_associated_data(
                        header.record_id,
                        header.storage_schema_version,
                    ),
                )
            )
            with data_key:
                plaintext = decrypt(ciphertext, prefix, nonce, data_key.copy_bytes())
            envelope = _deserialize_envelope(plaintext)
            if envelope.record_id != expected_record_id:
                raise StorageFailure(expected_record_id, StorageFailureCode.CORRUPT_RECORD)
            return DecodedStoredRecord(
                envelope=envelope,
                storage_schema_version=header.storage_schema_version,
                requires_migration=(
                    header.storage_schema_version < CURRENT_STORAGE_SCHEMA_VERSION
                ),
            )
        except StorageFailure:
            raise
        except (
            CryptoError,
            ValueError,
            ValidationError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            binascii.Error,
        ) as exc:
            raise StorageFailure(
                expected_record_id,
                StorageFailureCode.CORRUPT_RECORD,
            ) from exc


def _split_blob(blob: bytes) -> tuple[_BlobHeader, bytes, bytes, bytes, bytes]:
    if len(blob) > _MAX_BLOB_BYTES or len(blob) < len(_MAGIC) + _HEADER_SIZE_BYTES:
        raise ValueError("invalid blob length")
    if not blob.startswith(_MAGIC):
        raise ValueError("invalid blob magic")
    header_size_offset = len(_MAGIC)
    header_offset = header_size_offset + _HEADER_SIZE_BYTES
    header_size = int.from_bytes(blob[header_size_offset:header_offset], "big")
    if not 0 < header_size <= _MAX_HEADER_BYTES:
        raise ValueError("invalid header size")
    header_end = header_offset + header_size
    if header_end > len(blob):
        raise ValueError("truncated header")
    raw = cast(dict[str, Any], json.loads(blob[header_offset:header_end].decode("utf-8")))
    header = _BlobHeader.model_validate(raw)
    if (
        header.format_version != _OUTER_FORMAT_VERSION
        or header.algorithm != _OUTER_ALGORITHM
        or header.payload_format != _PAYLOAD_FORMAT
        or header.nonce_size != NONCE_BYTES
    ):
        raise ValueError("unsupported blob format")
    wrapped_end = header_end + header.wrapped_key_size
    nonce_end = wrapped_end + header.nonce_size
    ciphertext_end = nonce_end + header.ciphertext_size
    if ciphertext_end != len(blob):
        raise ValueError("blob frame sizes do not match")
    return (
        header,
        blob[:header_end],
        blob[header_end:wrapped_end],
        blob[wrapped_end:nonce_end],
        blob[nonce_end:ciphertext_end],
    )


def _serialize_envelope(envelope: EncryptedRecordEnvelope) -> bytes:
    payload = _EnvelopePayload(
        record_id=envelope.record_id,
        generation=envelope.generation.value,
        configuration_revision=envelope.configuration_revision,
        envelope_schema_version=envelope.schema_version,
        algorithm=envelope.algorithm,
        key_id=envelope.key.key_id,
        key_provider_id=envelope.key.provider_id,
        key_version=envelope.key.version,
        plaintext_frame_sizes=envelope.plaintext_frame_sizes,
        wrapped_data_key=_encode_bytes(envelope.wrapped_data_key),
        nonce=_encode_bytes(envelope.nonce),
        ciphertext=_encode_bytes(envelope.ciphertext),
        associated_data_digest=_encode_bytes(envelope.associated_data_digest),
        created_at=envelope.created_at,
    )
    return _canonical_model_bytes(payload)


def _deserialize_envelope(payload: bytes) -> EncryptedRecordEnvelope:
    raw = cast(dict[str, Any], json.loads(payload.decode("utf-8")))
    value = _EnvelopePayload.model_validate(raw)
    return EncryptedRecordEnvelope(
        record_id=value.record_id,
        generation=CaptureGeneration(value.generation),
        configuration_revision=value.configuration_revision,
        schema_version=value.envelope_schema_version,
        algorithm=value.algorithm,
        key=KeyHandle(
            key_id=value.key_id,
            provider_id=value.key_provider_id,
            version=value.key_version,
        ),
        plaintext_frame_sizes=value.plaintext_frame_sizes,
        wrapped_data_key=_decode_bytes(value.wrapped_data_key),
        nonce=_decode_bytes(value.nonce),
        ciphertext=_decode_bytes(value.ciphertext),
        associated_data_digest=_decode_bytes(value.associated_data_digest),
        created_at=value.created_at,
    )


def _canonical_model_bytes(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _wrap_associated_data(record_id: UUID, storage_schema_version: int) -> bytes:
    value = (
        b"local-recall-storage-key-wrap-v1\x00"
        + record_id.bytes
        + storage_schema_version.to_bytes(4, "big")
    )
    return hashlib.sha256(value).digest()


def _encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_bytes(value: str) -> bytes:
    decoded = base64.b64decode(value.encode("ascii"), validate=True)
    if not decoded:
        raise ValueError("decoded value must not be empty")
    return decoded
