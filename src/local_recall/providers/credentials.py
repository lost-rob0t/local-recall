from __future__ import annotations

from typing import Protocol

from local_recall.config import CredentialReference

from .remote import ResolvedCredential


class CredentialBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...


class CredentialResolutionError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if not reason_code:
            raise ValueError("credential resolution reason code must not be empty")
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:
        return f"CredentialResolutionError(reason_code={self.reason_code!r})"


class OSKeyringCredentialProvider:
    provider_id = "os-keyring"
    _SERVICE_NAME = "local-recall:remote-credentials"

    def __init__(self, backend: CredentialBackend) -> None:
        self._backend = backend

    @classmethod
    def from_system(cls) -> OSKeyringCredentialProvider:
        from local_recall.crypto.keyring import PythonKeyringBackend

        return cls(PythonKeyringBackend())

    def resolve(self, reference: CredentialReference) -> ResolvedCredential:
        if reference.provider_id != self.provider_id:
            raise CredentialResolutionError("credential-provider-mismatch")
        if any(character in reference.reference for character in ("\x00", "\r", "\n")):
            raise CredentialResolutionError("credential-reference-invalid")

        try:
            value = self._backend.get_password(self._SERVICE_NAME, reference.reference)
        except Exception as exc:
            raise CredentialResolutionError("credential-provider-unavailable") from exc
        if value is None:
            raise CredentialResolutionError("credential-not-found")
        try:
            return ResolvedCredential(value=value)
        except ValueError as exc:
            raise CredentialResolutionError("credential-invalid") from exc
