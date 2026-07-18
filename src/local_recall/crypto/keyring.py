from __future__ import annotations

import base64
import importlib
import secrets
from typing import Protocol, cast

from nacl.exceptions import CryptoError

from local_recall.domain.crypto import (
    KeyHandle,
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

from .bindings import KEY_BYTES, NONCE_BYTES, decrypt, encrypt
from .errors import KeyProviderFailure, KeyProviderFailureCode


class KeyringBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class KeyringBackendLocked(RuntimeError):
    pass


class _KeyringModule(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class PythonKeyringBackend:
    def __init__(self) -> None:
        try:
            module = importlib.import_module("keyring")
        except ImportError as exc:
            raise KeyProviderFailure(
                "os-keyring", KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc
        self._module = cast(_KeyringModule, module)

    def get_password(self, service: str, username: str) -> str | None:
        return self._module.get_password(service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        self._module.set_password(service, username, password)

    def delete_password(self, service: str, username: str) -> None:
        self._module.delete_password(service, username)


class OSKeyringProvider:
    provider_id = "os-keyring"

    def __init__(
        self,
        backend: KeyringBackend,
        *,
        service_name: str = "local-recall",
    ) -> None:
        self._backend = backend
        self._service_name = service_name

    @classmethod
    def from_system(cls, *, service_name: str = "local-recall") -> OSKeyringProvider:
        return cls(PythonKeyringBackend(), service_name=service_name)

    async def health(self, request: KeyRequest) -> KeyHealthReport:
        try:
            key = await self.active_key(
                KeyRequest(purpose=request.purpose, create_if_missing=False)
            )
        except KeyProviderFailure as exc:
            status = {
                KeyProviderFailureCode.KEY_LOCKED: KeyHealthStatus.LOCKED,
                KeyProviderFailureCode.KEY_NOT_FOUND: KeyHealthStatus.UNAVAILABLE,
                KeyProviderFailureCode.INVALID_KEY: KeyHealthStatus.INVALID,
                KeyProviderFailureCode.REVOKED: KeyHealthStatus.REVOKED,
            }.get(exc.code, KeyHealthStatus.UNAVAILABLE)
            return KeyHealthReport(self.provider_id, status)
        return KeyHealthReport(self.provider_id, KeyHealthStatus.READY, key)

    async def active_key(self, request: KeyRequest) -> KeyHandle:
        try:
            active = self._backend.get_password(
                self._service_name, self._active_username(request.purpose.value)
            )
        except KeyringBackendLocked as exc:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.KEY_LOCKED) from exc
        except Exception as exc:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc

        if active is None:
            if not request.create_if_missing:
                raise KeyProviderFailure(
                    self.provider_id, KeyProviderFailureCode.KEY_NOT_FOUND
                )
            return self._create_initial(request)

        try:
            version = int(active)
        except ValueError as exc:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY) from exc
        handle = self._handle(request.purpose.value, version)
        with self._load_master(handle):
            return handle

    async def wrap_data_key(self, request: KeyWrapRequest) -> bytes:
        with self._load_master(request.key) as master:
            nonce = secrets.token_bytes(NONCE_BYTES)
            ciphertext = encrypt(
                request.material.copy_bytes(),
                request.associated_data,
                nonce,
                master.copy_bytes(),
            )
            return nonce + ciphertext

    async def unwrap_data_key(self, request: KeyUnwrapRequest) -> SecretKeyMaterial:
        if len(request.wrapped_data_key) <= NONCE_BYTES:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        nonce = request.wrapped_data_key[:NONCE_BYTES]
        ciphertext = request.wrapped_data_key[NONCE_BYTES:]
        with self._load_master(request.key) as master:
            try:
                plaintext = decrypt(
                    ciphertext,
                    request.associated_data,
                    nonce,
                    master.copy_bytes(),
                )
            except CryptoError as exc:
                raise KeyProviderFailure(
                    self.provider_id, KeyProviderFailureCode.INVALID_KEY
                ) from exc
        return SecretKeyMaterial.from_bytes(plaintext)

    async def rotate(self, request: KeyRotationRequest) -> KeyHandle:
        self._validate_handle(request.current)
        with self._load_master(request.current):
            next_version = request.current.version + 1
        handle = self._handle(self._purpose_from_handle(request.current), next_version)
        self._store_master(handle, secrets.token_bytes(KEY_BYTES))
        self._set_active(self._purpose_from_handle(handle), next_version)
        return handle

    async def destroy(self, request: KeyDestructionRequest) -> KeyDestructionResult:
        self._validate_handle(request.key)
        purpose = self._purpose_from_handle(request.key)
        try:
            self._backend.delete_password(
                self._service_name, self._material_username(request.key)
            )
            active = self._backend.get_password(
                self._service_name, self._active_username(purpose)
            )
            if active == str(request.key.version):
                self._backend.delete_password(
                    self._service_name, self._active_username(purpose)
                )
        except KeyringBackendLocked as exc:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.KEY_LOCKED) from exc
        except Exception as exc:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc
        return KeyDestructionResult(request.key, destroyed=True)

    def _create_initial(self, request: KeyRequest) -> KeyHandle:
        handle = self._handle(request.purpose.value, 1)
        self._store_master(handle, secrets.token_bytes(KEY_BYTES))
        self._set_active(request.purpose.value, 1)
        return handle

    def _store_master(self, handle: KeyHandle, material: bytes) -> None:
        encoded = base64.b64encode(material).decode("ascii")
        try:
            self._backend.set_password(
                self._service_name, self._material_username(handle), encoded
            )
        except KeyringBackendLocked as exc:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.KEY_LOCKED) from exc
        except Exception as exc:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc

    def _set_active(self, purpose: str, version: int) -> None:
        try:
            self._backend.set_password(
                self._service_name, self._active_username(purpose), str(version)
            )
        except KeyringBackendLocked as exc:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.KEY_LOCKED) from exc
        except Exception as exc:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc

    def _load_master(self, handle: KeyHandle) -> SecretKeyMaterial:
        self._validate_handle(handle)
        try:
            encoded = self._backend.get_password(
                self._service_name, self._material_username(handle)
            )
        except KeyringBackendLocked as exc:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.KEY_LOCKED) from exc
        except Exception as exc:
            raise KeyProviderFailure(
                self.provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc
        if encoded is None:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.KEY_NOT_FOUND)
        try:
            material = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY) from exc
        if len(material) != KEY_BYTES:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        return SecretKeyMaterial.from_bytes(material)

    def _validate_handle(self, handle: KeyHandle) -> None:
        if handle.provider_id != self.provider_id:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        self._purpose_from_handle(handle)

    def _purpose_from_handle(self, handle: KeyHandle) -> str:
        suffix = "-master"
        if not handle.key_id.endswith(suffix):
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        purpose = handle.key_id[: -len(suffix)]
        if not purpose:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        return purpose

    def _handle(self, purpose: str, version: int) -> KeyHandle:
        if version <= 0:
            raise KeyProviderFailure(self.provider_id, KeyProviderFailureCode.INVALID_KEY)
        return KeyHandle(f"{purpose}-master", self.provider_id, version)

    @staticmethod
    def _active_username(purpose: str) -> str:
        return f"{purpose}:active"

    @staticmethod
    def _material_username(handle: KeyHandle) -> str:
        purpose = handle.key_id.removesuffix("-master")
        return f"{purpose}:v{handle.version}"
