from __future__ import annotations

from typing import Protocol, runtime_checkable

import keyring
from keyring import errors as keyring_errors

from local_recall.domain.crypto import KeyHandle, KeyRequest

from .errors import KeyProviderInvalid, KeyProviderLocked, KeyProviderUnavailable
from .models import KeyDestructionResult, KeyProviderHealth, KeyProviderState
from .primitives import random_key, unwrap_with_kek, wipe, wrap_with_kek
from .provider_shared import decode_key, encode_key, require_provider, require_reference


@runtime_checkable
class PasswordBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class _SystemKeyringBackend:
    def get_password(self, service: str, username: str) -> str | None:
        return keyring.get_password(service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        keyring.set_password(service, username, password)

    def delete_password(self, service: str, username: str) -> None:
        keyring.delete_password(service, username)


class OSKeyringProvider:
    def __init__(
        self,
        *,
        service_name: str = "local-recall",
        backend: PasswordBackend | None = None,
    ) -> None:
        self._service = service_name
        self._backend = backend or _SystemKeyringBackend()

    @property
    def provider_id(self) -> str:
        return "os-keyring"

    def health_check(self) -> KeyProviderHealth:
        try:
            self._backend.get_password(self._service, "__health__")
        except keyring_errors.KeyringLocked:
            return KeyProviderHealth(self.provider_id, KeyProviderState.LOCKED, "keyring_locked")
        except Exception:
            return KeyProviderHealth(
                self.provider_id, KeyProviderState.UNAVAILABLE, "keyring_unavailable"
            )
        return KeyProviderHealth(self.provider_id, KeyProviderState.HEALTHY, "healthy")

    def active_key(self, request: KeyRequest) -> KeyHandle:
        reference = require_reference(request)
        self._require_healthy()
        purpose = request.purpose.value
        version_text = self._get(self._active_name(reference, purpose))
        if version_text is None:
            if not request.create_if_missing:
                raise KeyProviderUnavailable("key_missing")
            version = 1
            self._put(self._key_name(reference, purpose, version), encode_key(random_key()))
            self._put(self._active_name(reference, purpose), str(version))
            return KeyHandle(reference, self.provider_id, version)
        try:
            version = int(version_text)
        except ValueError:
            raise KeyProviderInvalid("active_key_version_invalid") from None
        if version <= 0:
            raise KeyProviderInvalid("active_key_version_invalid")
        handle = KeyHandle(reference, self.provider_id, version)
        material = self._load_key(handle)
        wipe(material)
        return handle

    def wrap_data_key(self, key: KeyHandle, data_key: bytes, associated_data: bytes) -> bytes:
        material = self._load_key(key)
        try:
            return wrap_with_kek(bytes(material), data_key, associated_data)
        finally:
            wipe(material)

    def unwrap_data_key(
        self, key: KeyHandle, wrapped_data_key: bytes, associated_data: bytes
    ) -> bytearray:
        material = self._load_key(key)
        try:
            return unwrap_with_kek(bytes(material), wrapped_data_key, associated_data)
        finally:
            wipe(material)

    def rotate(self, current: KeyHandle, reason_code: str) -> KeyHandle:
        del reason_code
        material = self._load_key(current)
        wipe(material)
        version = current.version + 1
        self._put(self._key_name(current.key_id, "record", version), encode_key(random_key()))
        self._put(self._active_name(current.key_id, "record"), str(version))
        return KeyHandle(current.key_id, self.provider_id, version)

    def destroy(self, key: KeyHandle, reason_code: str) -> KeyDestructionResult:
        del reason_code
        require_provider(key, self.provider_id)
        name = self._key_name(key.key_id, "record", key.version)
        existed = self._get(name) is not None
        if existed:
            self._delete(name)
        active_name = self._active_name(key.key_id, "record")
        if self._get(active_name) == str(key.version):
            self._delete(active_name)
        return KeyDestructionResult(key, existed)

    def _require_healthy(self) -> None:
        health = self.health_check()
        if health.state is KeyProviderState.LOCKED:
            raise KeyProviderLocked(health.code)
        if not health.healthy:
            raise KeyProviderUnavailable(health.code)

    def _load_key(self, key: KeyHandle) -> bytearray:
        require_provider(key, self.provider_id)
        self._require_healthy()
        encoded = self._get(self._key_name(key.key_id, "record", key.version))
        if encoded is None:
            raise KeyProviderUnavailable("key_missing")
        return decode_key(encoded)

    def _get(self, username: str) -> str | None:
        try:
            return self._backend.get_password(self._service, username)
        except keyring_errors.KeyringLocked:
            raise KeyProviderLocked("keyring_locked") from None
        except Exception:
            raise KeyProviderUnavailable("keyring_unavailable") from None

    def _put(self, username: str, value: str) -> None:
        try:
            self._backend.set_password(self._service, username, value)
        except keyring_errors.KeyringLocked:
            raise KeyProviderLocked("keyring_locked") from None
        except Exception:
            raise KeyProviderUnavailable("keyring_unavailable") from None

    def _delete(self, username: str) -> None:
        try:
            self._backend.delete_password(self._service, username)
        except Exception:
            raise KeyProviderUnavailable("keyring_delete_failed") from None

    @staticmethod
    def _active_name(reference: str, purpose: str) -> str:
        return f"{reference}:{purpose}:active"

    @staticmethod
    def _key_name(reference: str, purpose: str, version: int) -> str:
        return f"{reference}:{purpose}:v{version}"
