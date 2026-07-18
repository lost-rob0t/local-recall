from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid1, uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.storage import StorageFailure, StorageFailureCode, decode_envelope, encode_envelope


def envelope() -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=uuid4(),
        generation=CaptureGeneration(3),
        configuration_revision="fixture-revision",
        schema_version=1,
        algorithm="xchacha20-poly1305-ietf",
        key=KeyHandle("fixture-key", "os-keyring", 2),
        plaintext_frame_sizes=(128, 64),
        wrapped_data_key=b"w" * 48,
        nonce=b"n" * 24,
        ciphertext=b"synthetic-ciphertext",
        associated_data_digest=b"d" * 32,
        created_at=datetime(2026, 7, 18, 12, 30, tzinfo=UTC),
    )


def test_persistent_envelope_round_trip() -> None:
    source = envelope()
    encoded = encode_envelope(source)

    assert decode_envelope(encoded, max_blob_bytes=len(encoded)) == source


def test_persistent_envelope_rejects_malformed_bytes() -> None:
    encoded = encode_envelope(envelope())

    with pytest.raises(StorageFailure, match="storage_corruption"):
        decode_envelope(encoded[:-1], max_blob_bytes=len(encoded))


def test_persistent_envelope_rejects_time_ordered_identifier() -> None:
    source = replace(envelope(), record_id=uuid1())

    with pytest.raises(StorageFailure) as captured:
        encode_envelope(source)

    assert captured.value.code is StorageFailureCode.INVALID_RECORD_ID
