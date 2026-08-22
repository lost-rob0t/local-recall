from __future__ import annotations

from importlib import import_module

import pytest

from local_recall.config import CredentialReference

credentials = import_module("local_recall.providers.credentials")
CredentialResolutionError = credentials.CredentialResolutionError
OSKeyringCredentialProvider = credentials.OSKeyringCredentialProvider


class FakeBackend:
    def __init__(self, values: dict[tuple[str, str], str] | None = None) -> None:
        self.values = values or {}
        self.lookups: list[tuple[str, str]] = []

    def get_password(self, service: str, username: str) -> str | None:
        self.lookups.append((service, username))
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        raise AssertionError("credential resolution must be read-only")

    def delete_password(self, service: str, username: str) -> None:
        raise AssertionError("credential resolution must be read-only")


def test_os_keyring_resolves_reference_only_at_transport_boundary() -> None:
    backend = FakeBackend(
        {
            ("local-recall:remote-credentials", "openrouter-main"): (
                "sk-or-v1-synthetic-value"  # pragma: allowlist secret
            )
        }
    )
    provider = OSKeyringCredentialProvider(backend)
    reference = CredentialReference(provider_id="os-keyring", reference="openrouter-main")

    credential = provider.resolve(reference)

    assert backend.lookups == [("local-recall:remote-credentials", "openrouter-main")]
    assert credential.value.startswith("sk-or-")
    assert credential.value not in repr(credential)
    assert reference.reference not in repr(reference)


def test_credential_provider_id_mismatch_fails_closed_without_lookup() -> None:
    backend = FakeBackend()
    provider = OSKeyringCredentialProvider(backend)

    with pytest.raises(CredentialResolutionError, match="credential-provider-mismatch"):
        provider.resolve(
            CredentialReference(provider_id="different-provider", reference="openrouter-main")
        )

    assert backend.lookups == []


def test_missing_credential_has_sanitized_error() -> None:
    provider = OSKeyringCredentialProvider(FakeBackend())
    reference = CredentialReference(provider_id="os-keyring", reference="private-reference-name")

    with pytest.raises(CredentialResolutionError, match="credential-not-found") as captured:
        provider.resolve(reference)

    assert reference.reference not in str(captured.value)
    assert reference.reference not in repr(captured.value)


def test_keyring_backend_failure_is_sanitized() -> None:
    class BrokenBackend(FakeBackend):
        def get_password(self, service: str, username: str) -> str | None:
            raise RuntimeError("backend dumped private-reference-name and secret material")

    provider = OSKeyringCredentialProvider(BrokenBackend())

    with pytest.raises(CredentialResolutionError, match="credential-provider-unavailable") as captured:
        provider.resolve(
            CredentialReference(provider_id="os-keyring", reference="private-reference-name")
        )

    rendered = f"{captured.value!s} {captured.value!r}"
    assert "private-reference-name" not in rendered
    assert "secret material" not in rendered
