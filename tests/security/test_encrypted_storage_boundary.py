from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

import pytest
from tests.storage_helpers import MemoryKeyProvider

from local_recall.domain.crypto import EncryptedRecordEnvelope
from local_recall.storage.filesystem import FilesystemStorageBackend


@pytest.mark.security
def test_storage_runtime_rejects_non_envelope_payloads(tmp_path: Path) -> None:
    backend = FilesystemStorageBackend(tmp_path / "store", MemoryKeyProvider())

    with pytest.raises(TypeError):
        asyncio.run(backend.put(cast(EncryptedRecordEnvelope, b"raw screenshot bytes")))


@pytest.mark.security
def test_storage_rejects_symlink_root(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "store"
    link.symlink_to(actual, target_is_directory=True)

    with pytest.raises(ValueError):
        FilesystemStorageBackend(link, MemoryKeyProvider())
