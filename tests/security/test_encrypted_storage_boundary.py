from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from local_recall.storage import FilesystemStorageBackend
from tests.storage_helpers import MemoryKeyProvider


def test_storage_runtime_rejects_plaintext_payloads(tmp_path: Path) -> None:
    backend = FilesystemStorageBackend(tmp_path, MemoryKeyProvider())

    with pytest.raises(TypeError, match="EncryptedRecordEnvelope"):
        asyncio.run(backend.put(b"synthetic plaintext"))  # type: ignore[arg-type]

    assert not tuple((tmp_path / "blobs").rglob("*.lre"))
    backend.close()


def test_storage_root_rejects_symlink_component(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "linked"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        FilesystemStorageBackend(link / "records", MemoryKeyProvider())
