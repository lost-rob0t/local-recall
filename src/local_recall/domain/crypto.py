from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from ._validation import require_aware, require_nonempty, require_nonempty_bytes
from .lifecycle import CaptureGeneration


class KeyPurpose(StrEnum):
    RECORD = "record"
    INDEX = "index"
    SUMMARY = "summary"
    BACKUP = "backup"


@dataclass(frozen=True, slots=True)
class KeyHandle:
    key_id: str
    provider_id: str
    version: int

    def __post_init__(self) -> None:
        require_nonempty(self.key_id, "key_id")
        require_nonempty(self.provider_id, "provider_id")
        if self.version <= 0:
            raise ValueError("key version must be positive")


@dataclass(frozen=True, slots=True)
class KeyRequest:
    purpose: KeyPurpose
    create_if_missing: bool = False


@dataclass(slots=True, repr=False)
class SecretKeyMaterial:
    _buffer: bytearray = field(repr=False)
    _destroyed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self._buffer:
            raise ValueError("secret key material must not be empty")

    @classmethod
    def random(cls, size: int) -> SecretKeyMaterial:
        if size <= 0:
            raise ValueError("secret key material size must be positive")
        return cls(bytearray(secrets.token_bytes(size)))

    @classmethod
    def from_bytes(cls, value: bytes) -> SecretKeyMaterial:
        require_nonempty_bytes(value, "secret key material")
        return cls(bytearray(value))

    @property
    def size(self) -> int:
        return len(self._buffer)

    @property
    def destroyed(self) -> bool:
        return self._destroyed

    def copy_bytes(self) -> bytes:
        if self._destroyed:
            raise RuntimeError("secret key material has been destroyed")
        return bytes(self._buffer)

    def destroy(self) -> None:
        self._buffer[:] = b"\x00" * len(self._buffer)
        self._destroyed = True

    def __enter__(self) -> SecretKeyMaterial:
        if self._destroyed:
            raise RuntimeError("secret key material has been destroyed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.destroy()

    def __repr__(self) -> str:
        return f"SecretKeyMaterial(size={self.size}, destroyed={self.destroyed})"


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedRecordEnvelope:
    record_id: UUID
    generation: CaptureGeneration
    configuration_revision: str
    schema_version: int
    algorithm: str
    key: KeyHandle
    plaintext_frame_sizes: tuple[int, ...]
    wrapped_data_key: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    associated_data_digest: bytes = field(repr=False)
    created_at: datetime

    def __post_init__(self) -> None:
        require_nonempty(self.configuration_revision, "configuration_revision")
        if self.schema_version <= 0:
            raise ValueError("envelope schema version must be positive")
        require_nonempty(self.algorithm, "algorithm")
        if not self.plaintext_frame_sizes or any(
            size <= 0 for size in self.plaintext_frame_sizes
        ):
            raise ValueError("plaintext frame sizes must be positive")
        require_nonempty_bytes(self.wrapped_data_key, "wrapped_data_key")
        require_nonempty_bytes(self.nonce, "nonce")
        require_nonempty_bytes(self.ciphertext, "ciphertext")
        require_nonempty_bytes(self.associated_data_digest, "associated_data_digest")
        require_aware(self.created_at, "created_at")

    def __repr__(self) -> str:
        return (
            f"EncryptedRecordEnvelope(record_id={self.record_id!r}, "
            f"generation={self.generation!r}, schema_version={self.schema_version}, "
            f"algorithm={self.algorithm!r}, key={self.key!r}, "
            f"frame_sizes={self.plaintext_frame_sizes!r}, "
            f"wrapped_key_bytes={len(self.wrapped_data_key)}, "
            f"nonce_bytes={len(self.nonce)}, ciphertext_bytes={len(self.ciphertext)}, "
            f"associated_data_digest_bytes={len(self.associated_data_digest)}, "
            f"created_at={self.created_at!r})"
        )


@dataclass(frozen=True, slots=True)
class StoredRecordRef:
    record_id: UUID
    storage_id: str
    envelope_schema_version: int

    def __post_init__(self) -> None:
        require_nonempty(self.storage_id, "storage_id")
        if self.envelope_schema_version <= 0:
            raise ValueError("envelope schema version must be positive")
