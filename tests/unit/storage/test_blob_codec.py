from __future__ import annotations

import asyncio

import pytest

from local_recall.storage import EncryptedBlobCodec, StorageFailure, StorageFailureCode
from tests.storage_helpers import MemoryKeyProvider, make_envelope


def test_blob_codec_round_trip_hides_inner_envelope_fields() -> None:
    codec = EncryptedBlobCodec(MemoryKeyProvider())
    envelope = make_envelope(marker=b"synthetic-visible-marker")

    blob = asyncio.run(codec.encode(envelope))
    decoded = asyncio.run(codec.decode(blob, expected_record_id=envelope.record_id))

    assert decoded.envelope == envelope
    assert not decoded.requires_migration
    assert b"synthetic-visible-marker" not in blob
    assert envelope.configuration_revision.encode() not in blob
    assert envelope.created_at.isoformat().encode() not in blob
    assert envelope.ciphertext not in blob
    assert envelope.wrapped_data_key not in blob


def test_blob_codec_rejects_authenticated_tampering() -> None:
    codec = EncryptedBlobCodec(MemoryKeyProvider())
    envelope = make_envelope()
    blob = bytearray(asyncio.run(codec.encode(envelope)))
    blob[-1] ^= 1

    with pytest.raises(StorageFailure) as captured:
        asyncio.run(codec.decode(bytes(blob), expected_record_id=envelope.record_id))

    assert captured.value.code is StorageFailureCode.CORRUPT_RECORD


def test_prior_storage_schema_is_detected_for_forward_migration() -> None:
    codec = EncryptedBlobCodec(MemoryKeyProvider())
    envelope = make_envelope()

    blob = asyncio.run(codec.encode(envelope, storage_schema_version=1))
    decoded = asyncio.run(codec.decode(blob, expected_record_id=envelope.record_id))

    assert decoded.envelope == envelope
    assert decoded.storage_schema_version == 1
    assert decoded.requires_migration
