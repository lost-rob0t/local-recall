from __future__ import annotations

from local_recall.domain.crypto import KeyHandle, KeyRequest

from .errors import KeyProviderUnavailable, KeyRevoked
from .models import KeyDestructionResult, KeyProviderHealth, KeyProviderState
from .primitives import random_key, unwrap_with_kek, wipe, wrap_with_kek
from .provider_shared import require_provider, require_reference


class InMemoryKeyProvider:
    """Synthetic provider for tests and contract verification."""

    def __init__(self, provider_id: str = "memory") -> None:
        self._provider_id = provider_id
        self._keys: dict[tuple[str, int], bytearray] = {}
        self._active: dict[str, int] = {}
        self._revoked: set[tuple[str, int]] = set()

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def health_check(self) -> KeyProviderHealth:
        return KeyProviderHealth(self.provider_id, KeyProviderState.HEALTHY, "healthy")

    def active_key(self, request: KeyRequest) -> KeyHandle:
        reference = require_reference(request)
        version = self._active.get(reference)
        if version is None:
            if not request.create_if_missing:
                raise KeyProviderUnavailable("key_missing")
            version = 1
            self._keys[(reference, version)] = random_key()
            self._active[reference] = version
        return KeyHandle(reference, self.provider_id, version)

    def wrap_data_key(self, key: KeyHandle, data_key: bytes, associated_data: bytes) -> bytes:
        return wrap_with_kek(bytes(self._load(key)), data_key, associated_data)

    def unwrap_data_key(
        self, key: KeyHandle, wrapped_data_key: bytes, associated_data: bytes
    ) -> bytearray:
        return unwrap_with_kek(bytes(self._load(key)), wrapped_data_key, associated_data)

    def rotate(self, current: KeyHandle, reason_code: str) -> KeyHandle:
        del reason_code
        self._load(current)
        version = current.version + 1
        self._keys[(current.key_id, version)] = random_key()
        self._active[current.key_id] = version
        return KeyHandle(current.key_id, self.provider_id, version)

    def destroy(self, key: KeyHandle, reason_code: str) -> KeyDestructionResult:
        del reason_code
        material = self._keys.pop((key.key_id, key.version), None)
        if material is not None:
            wipe(material)
        self._revoked.add((key.key_id, key.version))
        if self._active.get(key.key_id) == key.version:
            self._active.pop(key.key_id, None)
        return KeyDestructionResult(key, material is not None)

    def _load(self, key: KeyHandle) -> bytearray:
        require_provider(key, self.provider_id)
        if (key.key_id, key.version) in self._revoked:
            raise KeyRevoked("key_revoked")
        material = self._keys.get((key.key_id, key.version))
        if material is None:
            raise KeyProviderUnavailable("key_missing")
        return material
