from __future__ import annotations

from uuid import UUID


class CryptoError(RuntimeError):
    def __init__(self, code: str, *, record_id: UUID | None = None) -> None:
        self.code = code
        self.record_id = record_id
        suffix = f" for record {record_id}" if record_id is not None else ""
        super().__init__(f"cryptographic operation failed: {code}{suffix}")


class KeyProviderUnavailable(CryptoError):
    pass


class KeyProviderLocked(CryptoError):
    pass


class KeyProviderInvalid(CryptoError):
    pass


class KeyRevoked(CryptoError):
    pass


class AuthenticationFailed(CryptoError):
    pass


class EnvelopeFormatError(CryptoError):
    pass


class RotationError(CryptoError):
    pass
