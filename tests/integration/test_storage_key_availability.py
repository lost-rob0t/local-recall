from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from local_recall.crypto.errors import KeyProviderFailure, KeyProviderFailureCode
from local_recall.domain.crypto import SecretKeyMaterial
from local_recall.ports.keys import KeyUnwrapRequest
from local_recall.storage import FilesystemStorageBackend
from tests.storage_helpers import MemoryKeyProvider, make_envelope


class LockedMemoryKeyProvider(MemoryKeyProvider):
    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        del request
        raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.KEY_LOCKED)


def test_locked_storage_key_does_not_quarantine_valid_blob(tmp_path: Path) -> None:
    envelope = make_envelope()
    writable = FilesystemStorageBackend(tmp_path, MemoryKeyProvider())
    asyncio.run(writable.put(envelope))
    writable.close()

    locked = FilesystemStorageBackend(tmp_path, LockedMemoryKeyProvider())
    with pytest.raises(KeyProviderFailure) as captured:
        asyncio.run(locked.get(envelope.record_id))
    assert captured.value.code is KeyProviderFailureCode.KEY_LOCKED
    locked.close()

    recovered = FilesystemStorageBackend(tmp_path, MemoryKeyProvider())
    assert asyncio.run(recovered.get(envelope.record_id)) == envelope
    recovered.close()
