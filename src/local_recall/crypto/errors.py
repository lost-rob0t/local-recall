from __future__ import annotations

from enum import StrEnum
from uuid import UUID


class EncryptionFailureCode(StrEnum):
    AUTHENTICATION_FAILED = "authentication_failed"
    CANCELLED = "cancelled"
    CODEC_FAILURE = "codec_failure"
    KEY_UNAVAILABLE = "key_unavailable"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    REWRAP_FAILED = "rewrap_failed"


class KeyProviderFailureCode(StrEnum):
    INVALID_KEY = "invalid_key"
    KEY_LOCKED = "key_locked"
    KEY_NOT_FOUND = "key_not_found"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    REVOKED = "revoked"
    ROTATION_REQUIRES_RECONFIGURATION = "rotation_requires_reconfiguration"


class EncryptionFailure(RuntimeError):
    def __init__(self, record_id: UUID, code: EncryptionFailureCode) -> None:
        self.record_id = record_id
        self.code = code
        super().__init__(f"record {record_id}: encryption failure ({code.value})")


class KeyProviderFailure(RuntimeError):
    def __init__(self, provider_id: str, code: KeyProviderFailureCode) -> None:
        self.provider_id = provider_id
        self.code = code
        super().__init__(f"key provider {provider_id}: {code.value}")
