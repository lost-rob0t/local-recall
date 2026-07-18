from __future__ import annotations

import json
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.pipeline.models import EncryptedStageItem, RedactedStageItem

from .errors import EncryptionFailure, EncryptionFailureCode

_CODEC_VERSION = 1
_BINARY_FRAME_COUNT = 4


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)


class _EnvelopeHeader(_FrozenModel):
    codec_version: int
    record_id: UUID
    generation: int = Field(gt=0)
    configuration_revision: str = Field(min_length=1)
    schema_version: int = Field(gt=0)
    algorithm: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    key_provider_id: str = Field(min_length=1)
    key_version: int = Field(gt=0)
    plaintext_frame_sizes: tuple[int, ...]
    binary_frame_sizes: tuple[int, int, int, int]
    created_at: datetime


def encode_encrypted_stage(
    source: RedactedStageItem,
    envelope: EncryptedRecordEnvelope,
) -> EncryptedStageItem:
    _validate_identity(source, envelope)
    binary_frames = (
        envelope.wrapped_data_key,
        envelope.nonce,
        envelope.ciphertext,
        envelope.associated_data_digest,
    )
    header = _EnvelopeHeader(
        codec_version=_CODEC_VERSION,
        record_id=envelope.record_id,
        generation=envelope.generation.value,
        configuration_revision=envelope.configuration_revision,
        schema_version=envelope.schema_version,
        algorithm=envelope.algorithm,
        key_id=envelope.key.key_id,
        key_provider_id=envelope.key.provider_id,
        key_version=envelope.key.version,
        plaintext_frame_sizes=envelope.plaintext_frame_sizes,
        binary_frame_sizes=cast(tuple[int, int, int, int], tuple(map(len, binary_frames))),
        created_at=envelope.created_at,
    )
    header_bytes = json.dumps(
        header.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return EncryptedStageItem(
        record_id=source.record_id,
        generation=source.generation,
        configuration_revision=source.configuration_revision,
        deadline_monotonic_ns=source.deadline_monotonic_ns,
        frames=(header_bytes, *binary_frames),
    )


def decode_encrypted_stage(item: EncryptedStageItem) -> EncryptedRecordEnvelope:
    if len(item.frames) != _BINARY_FRAME_COUNT + 1:
        raise EncryptionFailure(item.record_id, EncryptionFailureCode.CODEC_FAILURE)
    header_bytes = item.frames[0]
    binary_frames = item.frames[1:]
    try:
        raw = cast(dict[str, Any], json.loads(header_bytes.decode("utf-8")))
        header = _EnvelopeHeader.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError) as exc:
        raise EncryptionFailure(item.record_id, EncryptionFailureCode.CODEC_FAILURE) from exc
    if header.codec_version != _CODEC_VERSION:
        raise EncryptionFailure(item.record_id, EncryptionFailureCode.CODEC_FAILURE)
    if (
        header.record_id != item.record_id
        or header.generation != item.generation.value
        or header.configuration_revision != item.configuration_revision
    ):
        raise EncryptionFailure(item.record_id, EncryptionFailureCode.CODEC_FAILURE)
    if tuple(map(len, binary_frames)) != header.binary_frame_sizes:
        raise EncryptionFailure(item.record_id, EncryptionFailureCode.CODEC_FAILURE)
    wrapped_data_key, nonce, ciphertext, associated_data_digest = binary_frames
    return EncryptedRecordEnvelope(
        record_id=header.record_id,
        generation=CaptureGeneration(header.generation),
        configuration_revision=header.configuration_revision,
        schema_version=header.schema_version,
        algorithm=header.algorithm,
        key=KeyHandle(
            key_id=header.key_id,
            provider_id=header.key_provider_id,
            version=header.key_version,
        ),
        plaintext_frame_sizes=header.plaintext_frame_sizes,
        wrapped_data_key=wrapped_data_key,
        nonce=nonce,
        ciphertext=ciphertext,
        associated_data_digest=associated_data_digest,
        created_at=header.created_at,
    )


def _validate_identity(
    source: RedactedStageItem,
    envelope: EncryptedRecordEnvelope,
) -> None:
    if (
        source.record_id != envelope.record_id
        or source.generation != envelope.generation
        or source.configuration_revision != envelope.configuration_revision
    ):
        raise EncryptionFailure(source.record_id, EncryptionFailureCode.CODEC_FAILURE)
