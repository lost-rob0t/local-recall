from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.domain.crypto import EncryptedRecordEnvelope, KeyHandle
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.storage import SQLiteEncryptedStorage, StorageFailure, StorageFailureCode


def envelope(ciphertext: bytes = b"synthetic-ciphertext") -> EncryptedRecordEnvelope:
    return EncryptedRecordEnvelope(
        record_id=uuid4(),
        generation=CaptureGeneration(3),
        configuration_revision="fixture-revision",
        schema_version=1,
        algorithm="xchacha20-poly1305-ietf",
        key=KeyHandle("fixture-key", "os-keyring", 2),
        plaintext_frame_sizes=(128,),
        wrapped_data_key=b"w" * 48,
        nonce=b"n" * 24,
        ciphertext=ciphertext,
        associated_data_digest=b"d" * 32,
        created_at=datetime(2026, 7, 18, 12, 30, tzinfo=UTC),
    )


def test_quota_counts_existing_opaque_files(tmp_path: Path) -> None:
    backend = SQLiteEncryptedStorage(tmp_path, quota_bytes=2_000, max_blob_bytes=1_500)
    asyncio.run(backend.put(envelope(b"a" * 700)))

    with pytest.raises(StorageFailure) as captured:
        asyncio.run(backend.put(envelope(b"b" * 700)))

    assert captured.value.code is StorageFailureCode.QUOTA_EXCEEDED


def test_storage_paths_and_files_are_owner_only(tmp_path: Path) -> None:
    backend = SQLiteEncryptedStorage(tmp_path, quota_bytes=1_000_000, max_blob_bytes=100_000)
    stored = asyncio.run(backend.put(envelope()))

    assert os.stat(backend.paths.root).st_mode & 0o777 == 0o700
    assert os.stat(backend.paths.catalog).st_mode & 0o777 == 0o600
    assert os.stat(backend.paths.blobs / stored.storage_id).st_mode & 0o777 == 0o600


def test_symlink_root_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(StorageFailure) as captured:
        SQLiteEncryptedStorage(link, quota_bytes=1_000_000, max_blob_bytes=100_000)

    assert captured.value.code is StorageFailureCode.UNSAFE_ROOT
