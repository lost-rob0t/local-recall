from __future__ import annotations

import asyncio

import pytest
from tests.storage_helpers import MemoryKeyProvider, make_envelope

from local_recall.storage.codec import (
    CURRENT_STORAGE_SCHEMA_VERSION,
    EncryptedBlobCodec,
)
from local_recall.storage.errors import StorageFailure


def test_blob_codec_round_trip_hides_inner_envelope_fields() -> None:
    envelope = make_envelope()
    codec = EncryptedBlobCodec(MemoryKeyProvider())

    blob = asyncio.run(codec.encode(envelope))
    decoded = asyncio.run(codec.decode(blob, expected_record_id=envelope.record_id))

    assert decoded.envelope == envelope
    assert decoded.storage_schema_version == CURRENT_STORAGE_SCHEMA_VERSION
    assert not decoded.requires_migration
    assert envelope.configuration_revision.encode() not in blob
    assert envelope.ciphertext not in blob
    assert envelope.created_at.isoformat().encode() not in blob


def test_blob_codec_marks_prior_schema_for_forward_migration() -> None:
    envelope = make_envelope()
    codec = EncryptedBlobCodec(MemoryKeyProvider())

    legacy = asyncio.run(codec.encode(envelope, storage_schema_version=1))
    decoded = asyncio.run(codec.decode(legacy, expected_record_id=envelope.record_id))

    assert decoded.envelope == envelope
    assert decoded.storage_schema_version == 1
    assert decoded.requires_migration


def test_blob_codec_rejects_tampering() -> None:
    envelope = make_envelope()
    codec = EncryptedBlobCodec(MemoryKeyProvider())
    blob = bytearray(asyncio.run(codec.encode(envelope)))
    blob[-1] ^= 1

    with pytest.raises(StorageFailure):
        asyncio.run(codec.decode(bytes(blob), expected_record_id=envelope.record_id))
