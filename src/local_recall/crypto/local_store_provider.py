from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from nacl import bindings, pwhash

from local_recall.domain.crypto import KeyHandle, KeyRequest

from .errors import (
    KeyProviderInvalid,
    KeyProviderLocked,
    KeyProviderUnavailable,
    KeyRevoked,
)
from .models import KeyDestructionResult, KeyProviderHealth, KeyProviderState
from .primitives import random_key, unwrap_with_kek, wipe, wrap_with_kek
from .provider_shared import (
    KEY_BYTES,
    NONCE_BYTES,
    decode_bytes,
    encode_bytes,
    require_provider,
    require_reference,
)

_STORE_SCHEMA_VERSION = 1
_STORE_MAX_BYTES = 1024 * 1024
_STORE_MAGIC = b"LRKS\x01"


class LocalKeyStoreProvider:
    def __init__(
        self,
        path: Path,
        passphrase_source: Callable[[], bytes | None],
        *,
        opslimit: int = pwhash.argon2id.OPSLIMIT_INTERACTIVE,
        memlimit: int = pwhash.argon2id.MEMLIMIT_INTERACTIVE,
    ) -> None:
        self._path = path
        self._passphrase_source = passphrase_source
        self._opslimit = opslimit
        self._memlimit = memlimit

    @property
    def provider_id(self) -> str:
        return "local-key-store"

    def health_check(self) -> KeyProviderHealth:
        passphrase = self._passphrase_source()
        if not passphrase:
            return KeyProviderHealth(self.provider_id, KeyProviderState.LOCKED, "passphrase_missing")
        if self._path.is_symlink():
            return KeyProviderHealth(self.provider_id, KeyProviderState.INVALID, "key_store_symlink")
        if not self._path.exists():
            return KeyProviderHealth(self.provider_id, KeyProviderState.HEALTHY, "empty_store")
        try:
            document = self._read_document()
            active = cast(dict[str, object], document["active"])
            if active:
                first_name, first_version = next(iter(active.items()))
                material = self._load_material(
                    document, first_name, int(cast(int, first_version)), bytes(passphrase)
                )
                wipe(material)
        except KeyProviderLocked:
            return KeyProviderHealth(self.provider_id, KeyProviderState.LOCKED, "passphrase_invalid")
        except Exception:
            return KeyProviderHealth(self.provider_id, KeyProviderState.INVALID, "key_store_invalid")
        return KeyProviderHealth(self.provider_id, KeyProviderState.HEALTHY, "healthy")

    def active_key(self, request: KeyRequest) -> KeyHandle:
        reference = require_reference(request)
        passphrase = self._require_passphrase()
        document = self._read_or_new_document()
        name = self._logical_name(reference, request.purpose.value)
        active = cast(dict[str, object], document["active"])
        version_value = active.get(name)
        if version_value is None:
            if not request.create_if_missing:
                raise KeyProviderUnavailable("key_missing")
            version = 1
            self._insert_material(document, name, version, random_key(), passphrase)
            active[name] = version
            self._write_document(document)
        else:
            version = int(cast(int, version_value))
            material = self._load_material(document, name, version, passphrase)
            wipe(material)
        return KeyHandle(reference, self.provider_id, version)

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
        require_provider(current, self.provider_id)
        passphrase = self._require_passphrase()
        document = self._read_document()
        name = self._logical_name(current.key_id, "record")
        material = self._load_material(document, name, current.version, passphrase)
        wipe(material)
        version = current.version + 1
        self._insert_material(document, name, version, random_key(), passphrase)
        cast(dict[str, object], document["active"])[name] = version
        self._write_document(document)
        return KeyHandle(current.key_id, self.provider_id, version)

    def destroy(self, key: KeyHandle, reason_code: str) -> KeyDestructionResult:
        del reason_code
        require_provider(key, self.provider_id)
        document = self._read_document()
        name = self._logical_name(key.key_id, "record")
        entry_name = self._entry_name(name, key.version)
        keys = cast(dict[str, object], document["keys"])
        existed = keys.pop(entry_name, None) is not None
        revoked = cast(list[str], document["revoked"])
        if entry_name not in revoked:
            revoked.append(entry_name)
        active = cast(dict[str, object], document["active"])
        if active.get(name) == key.version:
            active.pop(name, None)
        self._write_document(document)
        return KeyDestructionResult(key, existed)

    def _load_key(self, key: KeyHandle) -> bytearray:
        require_provider(key, self.provider_id)
        document = self._read_document()
        name = self._logical_name(key.key_id, "record")
        return self._load_material(document, name, key.version, self._require_passphrase())

    def _read_or_new_document(self) -> dict[str, object]:
        if self._path.is_symlink():
            raise KeyProviderInvalid("key_store_symlink")
        if self._path.exists():
            return self._read_document()
        return {
            "schema_version": _STORE_SCHEMA_VERSION,
            "salt": encode_bytes(os.urandom(pwhash.argon2id.SALTBYTES)),
            "active": {},
            "keys": {},
            "revoked": [],
        }

    def _read_document(self) -> dict[str, object]:
        if self._path.is_symlink():
            raise KeyProviderInvalid("key_store_symlink")
        stat = self._path.stat()
        if not self._path.is_file() or stat.st_size > _STORE_MAX_BYTES:
            raise KeyProviderInvalid("key_store_invalid")
        try:
            parsed_object: object = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            raise KeyProviderInvalid("key_store_invalid") from None
        if not isinstance(parsed_object, dict):
            raise KeyProviderInvalid("key_store_schema_invalid")
        parsed = cast(dict[str, object], parsed_object)
        if parsed.get("schema_version") != _STORE_SCHEMA_VERSION:
            raise KeyProviderInvalid("key_store_schema_invalid")
        for name, expected in (("active", dict), ("keys", dict), ("revoked", list)):
            if not isinstance(parsed.get(name), expected):
                raise KeyProviderInvalid("key_store_invalid")
        decode_bytes(cast(str, parsed.get("salt", "")), expected=pwhash.argon2id.SALTBYTES)
        return parsed

    def _write_document(self, document: Mapping[str, object]) -> None:
        if self._path.is_symlink():
            raise KeyProviderInvalid("key_store_symlink")
        parent = self._path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > _STORE_MAX_BYTES:
            raise KeyProviderInvalid("key_store_too_large")
        descriptor, name = tempfile.mkstemp(dir=parent, prefix=".local-recall-key-")
        temp_path = Path(name)
        try:
            os.chmod(temp_path, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise KeyProviderUnavailable("key_store_write_failed") from None

    def _insert_material(
        self,
        document: dict[str, object],
        name: str,
        version: int,
        material: bytearray,
        passphrase: bytes,
    ) -> None:
        try:
            store_key = bytearray(self._derive_store_key(document, passphrase))
            nonce = os.urandom(NONCE_BYTES)
            aad = self._entry_name(name, version).encode()
            try:
                ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                    bytes(material), aad, nonce, bytes(store_key)
                )
            finally:
                wipe(store_key)
            cast(dict[str, object], document["keys"])[self._entry_name(name, version)] = {
                "nonce": encode_bytes(nonce),
                "ciphertext": encode_bytes(_STORE_MAGIC + ciphertext),
            }
        finally:
            wipe(material)

    def _load_material(
        self, document: Mapping[str, object], name: str, version: int, passphrase: bytes
    ) -> bytearray:
        entry_name = self._entry_name(name, version)
        if entry_name in cast(list[str], document["revoked"]):
            raise KeyRevoked("key_revoked")
        entry_object = cast(dict[str, object], document["keys"]).get(entry_name)
        if not isinstance(entry_object, dict):
            raise KeyProviderUnavailable("key_missing")
        entry = cast(dict[str, object], entry_object)
        nonce = decode_bytes(cast(str, entry.get("nonce", "")), expected=NONCE_BYTES)
        encoded = decode_bytes(cast(str, entry.get("ciphertext", "")))
        if not encoded.startswith(_STORE_MAGIC):
            raise KeyProviderInvalid("key_store_entry_invalid")
        store_key = bytearray(self._derive_store_key(document, passphrase))
        try:
            plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                encoded[len(_STORE_MAGIC) :], entry_name.encode(), nonce, bytes(store_key)
            )
        except Exception:
            raise KeyProviderLocked("passphrase_invalid") from None
        finally:
            wipe(store_key)
        if len(plaintext) != KEY_BYTES:
            raise KeyProviderInvalid("key_store_entry_invalid")
        return bytearray(plaintext)

    def _derive_store_key(self, document: Mapping[str, object], passphrase: bytes) -> bytes:
        salt = decode_bytes(cast(str, document["salt"]), expected=pwhash.argon2id.SALTBYTES)
        try:
            return pwhash.argon2id.kdf(
                KEY_BYTES,
                passphrase,
                salt,
                opslimit=self._opslimit,
                memlimit=self._memlimit,
            )
        except Exception:
            raise KeyProviderLocked("passphrase_invalid") from None

    def _require_passphrase(self) -> bytes:
        value = self._passphrase_source()
        if not value:
            raise KeyProviderLocked("passphrase_missing")
        return bytes(value)

    @staticmethod
    def _logical_name(reference: str, purpose: str) -> str:
        return f"{purpose}:{reference}"

    @staticmethod
    def _entry_name(name: str, version: int) -> str:
        return f"{name}:v{version}"
