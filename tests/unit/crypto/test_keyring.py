from __future__ import annotations

import asyncio

import pytest

from local_recall.crypto import (
    KeyProviderFailure,
    KeyProviderFailureCode,
    KeyringBackendLocked,
    OSKeyringProvider,
)
from local_recall.domain.crypto import KeyPurpose, KeyRequest, SecretKeyMaterial
from local_recall.ports.keys import (
    KeyDestructionRequest,
    KeyHealthStatus,
    KeyRotationRequest,
    KeyUnwrapRequest,
    KeyWrapRequest,
)


class MemoryBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.locked = False

    def get_password(self, service: str, username: str) -> str | None:
        self._check()
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._check()
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self._check()
        self.values.pop((service, username), None)

    def _check(self) -> None:
        if self.locked:
            raise KeyringBackendLocked("locked")


def test_health_reports_missing_and_ready_keys() -> None:
    backend = MemoryBackend()
    provider = OSKeyringProvider(backend)
    request = KeyRequest(KeyPurpose.RECORD)

    missing = asyncio.run(provider.health(request))
    created = asyncio.run(
        provider.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True))
    )
    ready = asyncio.run(provider.health(request))

    assert missing.status is KeyHealthStatus.UNAVAILABLE
    assert ready.status is KeyHealthStatus.READY
    assert ready.key == created


def test_keyring_wrap_and_unwrap_round_trip() -> None:
    provider = OSKeyringProvider(MemoryBackend())
    key = asyncio.run(
        provider.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True))
    )
    material = SecretKeyMaterial.from_bytes(bytes(range(32)))
    wrapped = asyncio.run(
        provider.wrap_data_key(KeyWrapRequest(key, material, b"synthetic-associated-data"))
    )
    recovered = asyncio.run(
        provider.unwrap_data_key(KeyUnwrapRequest(key, wrapped, b"synthetic-associated-data"))
    )

    assert recovered.copy_bytes() == bytes(range(32))
    material.destroy()
    recovered.destroy()


def test_rotation_keeps_old_version_available_until_revoked() -> None:
    provider = OSKeyringProvider(MemoryBackend())
    original = asyncio.run(
        provider.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True))
    )
    material = SecretKeyMaterial.from_bytes(bytes(range(32)))
    wrapped = asyncio.run(
        provider.wrap_data_key(KeyWrapRequest(original, material, b"rewrap-aad"))
    )
    rotated = asyncio.run(provider.rotate(KeyRotationRequest(original, "scheduled")))
    recovered = asyncio.run(
        provider.unwrap_data_key(KeyUnwrapRequest(original, wrapped, b"rewrap-aad"))
    )

    assert rotated.version == 2
    assert recovered.copy_bytes() == bytes(range(32))
    material.destroy()
    recovered.destroy()


def test_revoked_key_can_no_longer_unwrap() -> None:
    provider = OSKeyringProvider(MemoryBackend())
    key = asyncio.run(
        provider.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True))
    )
    material = SecretKeyMaterial.from_bytes(bytes(range(32)))
    wrapped = asyncio.run(provider.wrap_data_key(KeyWrapRequest(key, material, b"aad")))
    result = asyncio.run(provider.destroy(KeyDestructionRequest(key, "revocation")))

    assert result.destroyed
    with pytest.raises(KeyProviderFailure) as captured:
        asyncio.run(provider.unwrap_data_key(KeyUnwrapRequest(key, wrapped, b"aad")))
    assert captured.value.code is KeyProviderFailureCode.KEY_NOT_FOUND
    material.destroy()


def test_locked_keyring_fails_closed_without_backend_details() -> None:
    backend = MemoryBackend()
    backend.locked = True
    provider = OSKeyringProvider(backend)

    with pytest.raises(KeyProviderFailure) as captured:
        asyncio.run(
            provider.active_key(KeyRequest(KeyPurpose.RECORD, create_if_missing=True))
        )

    assert captured.value.code is KeyProviderFailureCode.KEY_LOCKED
    assert "locked" not in str(captured.value)
