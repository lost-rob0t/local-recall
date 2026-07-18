from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from ._validation import require_aware, require_nonempty, require_nonempty_bytes


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
    reference: str | None = None

    def __post_init__(self) -> None:
        if self.reference is not None:
            require_nonempty(self.reference, "reference")


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedRecordEnvelope:
    record_id: UUID
    schema_version: int
    algorithm: str
    key: KeyHandle
    wrapped_data_key: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    associated_data_digest: bytes = field(repr=False)
    created_at: datetime
    associated_data: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        if self.schema_version <= 0:
            raise ValueError("envelope schema version must be positive")
        require_nonempty(self.algorithm, "algorithm")
        require_nonempty_bytes(self.wrapped_data_key, "wrapped_data_key")
        require_nonempty_bytes(self.nonce, "nonce")
        require_nonempty_bytes(self.ciphertext, "ciphertext")
        require_nonempty_bytes(self.associated_data_digest, "associated_data_digest")
        require_aware(self.created_at, "created_at")
        if self.schema_version >= 2:
            require_nonempty_bytes(self.associated_data, "associated_data")

    def __repr__(self) -> str:
        return (
            f"EncryptedRecordEnvelope(record_id={self.record_id!r}, "
            f"schema_version={self.schema_version}, algorithm={self.algorithm!r}, "
            f"key={self.key!r}, wrapped_key_bytes={len(self.wrapped_data_key)}, "
            f"nonce_bytes={len(self.nonce)}, ciphertext_bytes={len(self.ciphertext)}, "
            f"associated_data_bytes={len(self.associated_data)}, "
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
