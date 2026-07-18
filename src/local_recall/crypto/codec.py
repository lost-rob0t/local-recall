from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle

from .errors import EnvelopeFormatError

_CODEC_VERSION = 1
_FRAME_COUNT = 6
_MAX_HEADER_BYTES = 16 * 1024
_MAX_ASSOCIATED_DATA_BYTES = 64 * 1024
_MAX_WRAPPED_KEY_BYTES = 1024 * 1024
_MAX_CIPHERTEXT_BYTES = 256 * 1024 * 1024


class _EnvelopeHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    codec_version: int = Field(ge=1)
    record_id: UUID
    schema_version: int = Field(ge=1)
    algorithm: str = Field(min_length=1, max_length=128)
    provider_id: str = Field(min_length=1, max_length=128)
    key_id: str = Field(min_length=1, max_length=512)
    key_version: int = Field(ge=1)
    created_at: datetime
    associated_data_bytes: int = Field(ge=1, le=_MAX_ASSOCIATED_DATA_BYTES)
    wrapped_data_key_bytes: int = Field(ge=1, le=_MAX_WRAPPED_KEY_BYTES)
    nonce_bytes: int = Field(ge=1, le=128)
    ciphertext_bytes: int = Field(ge=1, le=_MAX_CIPHERTEXT_BYTES)
    digest_bytes: int = Field(ge=1, le=128)


def encode_envelope(envelope: EncryptedRecordEnvelope) -> tuple[bytes, ...]:
    header = _EnvelopeHeader(
        codec_version=_CODEC_VERSION,
        record_id=envelope.record_id,
        schema_version=envelope.schema_version,
        algorithm=envelope.algorithm,
        provider_id=envelope.key.provider_id,
        key_id=envelope.key.key_id,
        key_version=envelope.key.version,
        created_at=envelope.created_at,
        associated_data_bytes=len(envelope.associated_data),
        wrapped_data_key_bytes=len(envelope.wrapped_data_key),
        nonce_bytes=len(envelope.nonce),
        ciphertext_bytes=len(envelope.ciphertext),
        digest_bytes=len(envelope.associated_data_digest),
    )
    header_bytes = json.dumps(
        header.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(header_bytes) > _MAX_HEADER_BYTES:
        raise EnvelopeFormatError("envelope_header_too_large", record_id=envelope.record_id)
    return (
        header_bytes,
        envelope.associated_data,
        envelope.wrapped_data_key,
        envelope.nonce,
        envelope.ciphertext,
        envelope.associated_data_digest,
    )


def decode_envelope(frames: tuple[bytes, ...]) -> EncryptedRecordEnvelope:
    if len(frames) != _FRAME_COUNT:
        raise EnvelopeFormatError("envelope_frame_count_invalid")
    if not frames[0] or len(frames[0]) > _MAX_HEADER_BYTES:
        raise EnvelopeFormatError("envelope_header_invalid")
    try:
        raw = json.loads(frames[0])
        header = _EnvelopeHeader.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError, ValueError):
        raise EnvelopeFormatError("envelope_header_invalid") from None
    if header.codec_version != _CODEC_VERSION:
        raise EnvelopeFormatError("envelope_codec_version_unsupported", record_id=header.record_id)
    expected = (
        header.associated_data_bytes,
        header.wrapped_data_key_bytes,
        header.nonce_bytes,
        header.ciphertext_bytes,
        header.digest_bytes,
    )
    actual = tuple(len(frame) for frame in frames[1:])
    if actual != expected:
        raise EnvelopeFormatError("envelope_frame_lengths_invalid", record_id=header.record_id)
    return EncryptedRecordEnvelope(
        record_id=header.record_id,
        schema_version=header.schema_version,
        algorithm=header.algorithm,
        key=KeyHandle(header.key_id, header.provider_id, header.key_version),
        wrapped_data_key=frames[2],
        nonce=frames[3],
        ciphertext=frames[4],
        associated_data_digest=frames[5],
        created_at=header.created_at,
        associated_data=frames[1],
    )
