from __future__ import annotations

from enum import IntEnum, StrEnum


class PrivacyClass(IntEnum):
    PUBLIC = 0
    OPERATIONAL_METADATA = 10
    REDACTED_CONTENT = 20
    ENCRYPTED_CONTENT = 30
    RAW_CAPTURE = 40
    SECRET_MATERIAL = 50


class ProviderLocation(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"
