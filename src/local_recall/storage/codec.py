from __future__ import annotations

import json
import struct
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration

from .errors import StorageFailure, StorageFailureCode

_MAGIC = b"LRBLOB01"
_FORMAT_VERSION = 1
_MAX_HEADER_BYTES = 64 * 1024
_MAX_BINARY_PART = 512 * 1024 * 1024
_HEADER_PREFIX = struct.Struct(">8sHI")
_LENGTHS = struct.Struct(">IIQI")
_REQUIRED_KEYS = {
    "record_id",
    "generation",
    "configuration_revision",
    "schema_version",
    "algorithm",
    "key_id",
    "key_provider_id",
    "key_version",
    "plaintext_frame_sizes",
    "created_at",
}


def encode_envelope(envelope: EncryptedRecordEnvelope) -> bytes:
    if not isinstance(envelope, EncryptedRecordEnvelope):
        raise StorageFailure(StorageFailureCode.INVALID_TYPE)
    _validate_uuid(envelope.record_id)
    header = {
        "record_id": str(envelope.record_id),
        "generation": envelope.generation.value,
        "configuration_revision": envelope.configuration_revision,
        "schema_version": envelope.schema_version,
        "algorithm": envelope.algorithm,
        "key_id": envelope.key.key_id,
        "key_provider_id": envelope.key.provider_id,
        "key_version": envelope.key.version,
        "plaintext_frame_sizes": list(envelope.plaintext_frame_sizes),
        "created_at": envelope.created_at.isoformat(),
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(header_bytes) > _MAX_HEADER_BYTES:
        raise StorageFailure(StorageFailureCode.BLOB_TOO_LARGE, record_id=envelope.record_id)
    parts = (
        envelope.wrapped_data_key,
        envelope.nonce,
        envelope.ciphertext,
        envelope.associated_data_digest,
    )
    if any(not part or len(part) > _MAX_BINARY_PART for part in parts):
        raise StorageFailure(StorageFailureCode.BLOB_TOO_LARGE, record_id=envelope.record_id)
    if len(envelope.associated_data_digest) != 32:
        raise StorageFailure(StorageFailureCode.CORRUPTION, record_id=envelope.record_id)
    return (
        _HEADER_PREFIX.pack(_MAGIC, _FORMAT_VERSION, len(header_bytes))
        + _LENGTHS.pack(*(len(part) for part in parts))
        + header_bytes
        + b"".join(parts)
    )


def decode_envelope(data: bytes, *, max_blob_bytes: int) -> EncryptedRecordEnvelope:
    if max_blob_bytes <= 0:
        raise ValueError("max_blob_bytes must be positive")
    minimum = _HEADER_PREFIX.size + _LENGTHS.size
    if not isinstance(data, bytes) or not data or len(data) > max_blob_bytes or len(data) < minimum:
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    magic, version, header_len = _HEADER_PREFIX.unpack_from(data)
    if magic != _MAGIC or version != _FORMAT_VERSION or not 1 <= header_len <= _MAX_HEADER_BYTES:
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    lengths = _LENGTHS.unpack_from(data, _HEADER_PREFIX.size)
    if any(length <= 0 or length > _MAX_BINARY_PART for length in lengths):
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    if lengths[-1] != 32:
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    offset = minimum
    expected = offset + header_len + sum(lengths)
    if expected != len(data):
        raise StorageFailure(StorageFailureCode.CORRUPTION)
    try:
        decoded: object = json.loads(data[offset : offset + header_len].decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError
        raw = cast(dict[str, Any], decoded)
        if set(raw) != _REQUIRED_KEYS:
            raise ValueError
        record_id_value = raw["record_id"]
        if not isinstance(record_id_value, str):
            raise ValueError
        record_id = UUID(record_id_value)
        _validate_uuid(record_id)
        generation_object = raw["generation"]
        schema_version_object = raw["schema_version"]
        key_version_object = raw["key_version"]
        if (
            type(generation_object) is not int
            or type(schema_version_object) is not int
            or type(key_version_object) is not int
        ):
            raise ValueError
        generation = cast(int, generation_object)
        schema_version = cast(int, schema_version_object)
        key_version = cast(int, key_version_object)
        sizes_object = raw["plaintext_frame_sizes"]
        if not isinstance(sizes_object, list) or any(
            type(value) is not int for value in sizes_object
        ):
            raise ValueError
        sizes = tuple(cast(int, value) for value in sizes_object)
        created_at_value = raw["created_at"]
        if not isinstance(created_at_value, str):
            raise ValueError
        created_at = datetime.fromisoformat(created_at_value)
        if generation <= 0 or schema_version <= 0 or key_version <= 0 or created_at.tzinfo is None:
            raise ValueError
        if not sizes or any(value <= 0 for value in sizes):
            raise ValueError
        configuration_revision = raw["configuration_revision"]
        algorithm = raw["algorithm"]
        key_id = raw["key_id"]
        key_provider_id = raw["key_provider_id"]
        strings = (configuration_revision, algorithm, key_id, key_provider_id)
        if any(not isinstance(value, str) or not value for value in strings):
            raise ValueError
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        raise StorageFailure(StorageFailureCode.CORRUPTION) from None
    cursor = offset + header_len
    parts: list[bytes] = []
    for length in lengths:
        parts.append(data[cursor : cursor + length])
        cursor += length
    wrapped, nonce, ciphertext, associated_data_digest = parts
    try:
        return EncryptedRecordEnvelope(
            record_id=record_id,
            generation=CaptureGeneration(generation),
            configuration_revision=cast(str, configuration_revision),
            schema_version=schema_version,
            algorithm=cast(str, algorithm),
            key=KeyHandle(
                cast(str, key_id),
                cast(str, key_provider_id),
                key_version,
            ),
            plaintext_frame_sizes=sizes,
            wrapped_data_key=wrapped,
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data_digest=associated_data_digest,
            created_at=created_at,
        )
    except ValueError:
        raise StorageFailure(StorageFailureCode.CORRUPTION, record_id=record_id) from None


def _validate_uuid(record_id: UUID) -> None:
    if record_id.version != 4:
        raise StorageFailure(StorageFailureCode.INVALID_RECORD_ID, record_id=record_id)
