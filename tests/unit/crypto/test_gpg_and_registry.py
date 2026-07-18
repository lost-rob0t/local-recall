from __future__ import annotations

import asyncio

import pytest

from local_recall.crypto import (
    GPGCommandResult,
    GPGKeyProvider,
    KeyProviderFailure,
    KeyProviderRegistry,
)
from local_recall.domain.crypto import (
    KeyHandle,
    KeyPurpose,
    KeyRequest,
    SecretKeyMaterial,
)
from local_recall.ports.keys import (
    KeyDestructionRequest,
    KeyDestructionResult,
    KeyHealthReport,
    KeyHealthStatus,
    KeyRotationRequest,
    KeyUnwrapRequest,
    KeyWrapRequest,
)


class FakeGPGRunner:
    def run(
        self,
        arguments: tuple[str, ...],
        input_data: bytes,
        timeout_seconds: float,
    ) -> GPGCommandResult:
        assert timeout_seconds > 0
        if "--list-keys" in arguments:
            return GPGCommandResult(0, b"pub:-:4096:1:synthetic")
        if "--encrypt" in arguments:
            return GPGCommandResult(0, b"sealed:" + input_data)
        if "--decrypt" in arguments and input_data.startswith(b"sealed:"):
            return GPGCommandResult(0, input_data.removeprefix(b"sealed:"))
        return GPGCommandResult(1, b"")


class UnavailableProvider:
    provider_id = "unavailable"

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        del request
        return KeyHealthReport(self.provider_id, KeyHealthStatus.UNAVAILABLE)

    async def active_key(self, request: KeyRequest) -> KeyHandle:
        del request
        raise AssertionError("unavailable provider must not be invoked")

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes:
        del request
        raise AssertionError("unavailable provider must not be invoked")

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        del request
        raise AssertionError("unavailable provider must not be invoked")

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle:
        del request
        raise AssertionError("unavailable provider must not be invoked")

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult:
        del request
        raise AssertionError("unavailable provider must not be invoked")


def test_gpg_wrap_and_unwrap_requires_health_checked_recipient() -> None:
    provider = GPGKeyProvider("synthetic-recipient", runner=FakeGPGRunner())
    request = KeyRequest(KeyPurpose.RECORD)
    health = asyncio.run(provider.health(request))
    key = asyncio.run(provider.active_key(request))
    material = SecretKeyMaterial.from_bytes(bytes(range(32)))
    wrapped = asyncio.run(provider.wrap_data_key(KeyWrapRequest(key, material, b"associated-data")))
    unwrapped = asyncio.run(
        provider.unwrap_data_key(KeyUnwrapRequest(key, wrapped, b"associated-data"))
    )

    assert health.status is KeyHealthStatus.READY
    assert unwrapped.copy_bytes() == bytes(range(32))
    material.destroy()
    unwrapped.destroy()


def test_gpg_associated_data_mismatch_is_rejected() -> None:
    provider = GPGKeyProvider("synthetic-recipient", runner=FakeGPGRunner())
    key = asyncio.run(provider.active_key(KeyRequest(KeyPurpose.RECORD)))
    material = SecretKeyMaterial.from_bytes(bytes(range(32)))
    wrapped = asyncio.run(provider.wrap_data_key(KeyWrapRequest(key, material, b"first")))

    with pytest.raises(KeyProviderFailure):
        asyncio.run(provider.unwrap_data_key(KeyUnwrapRequest(key, wrapped, b"second")))
    material.destroy()


def test_registry_never_selects_gpg_silently() -> None:
    gpg = GPGKeyProvider("synthetic-recipient", runner=FakeGPGRunner())
    registry = KeyProviderRegistry((UnavailableProvider(), gpg))
    request = KeyRequest(KeyPurpose.RECORD)

    with pytest.raises(KeyProviderFailure):
        asyncio.run(registry.select("unavailable", request))

    selection = asyncio.run(
        registry.select(
            "unavailable",
            request,
            explicit_fallback_provider_id="gpg",
        )
    )

    assert selection.provider is gpg
    assert selection.used_explicit_fallback
