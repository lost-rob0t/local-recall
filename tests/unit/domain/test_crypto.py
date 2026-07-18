from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle


def envelope() -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=uuid4(),
        schema_version=1,
        algorithm="xchacha20-poly1305",
        key=KeyHandle(key_id="key-1", provider_id="synthetic", version=1),
        wrapped_data_key=b"wrapped-key",
        nonce=b"nonce-value",
        ciphertext=b"ciphertext-value",
        associated_data_digest=b"digest-value",
        created_at=datetime.now(UTC),
    )


def test_envelope_requires_positive_schema_version() -> None:
    with pytest.raises(ValueError, match="schema version"):
        EncryptedRecordEnvelope(
            record_id=uuid4(),
            schema_version=0,
            algorithm="xchacha20-poly1305",
            key=KeyHandle(key_id="key-1", provider_id="synthetic", version=1),
            wrapped_data_key=b"wrapped",
            nonce=b"nonce",
            ciphertext=b"ciphertext",
            associated_data_digest=b"digest",
            created_at=datetime.now(UTC),
        )


def test_envelope_repr_hides_crypto_material() -> None:
    rendered = repr(envelope())

    assert "ciphertext-value" not in rendered
    assert "wrapped-key" not in rendered
    assert "nonce-value" not in rendered
