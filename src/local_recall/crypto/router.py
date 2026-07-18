from __future__ import annotations

from collections.abc import Iterable

from local_recall.config.models import CredentialReference, EncryptionSettings
from local_recall.domain.crypto import KeyHandle, KeyPurpose, KeyRequest

from .errors import KeyProviderInvalid, KeyProviderLocked, KeyProviderUnavailable
from .models import KeyProviderSelection, KeyProviderState, WrappingKeyProvider


class KeyProviderRouter:
    """Selects configured key providers without implicit fallback."""

    def __init__(self, providers: Iterable[WrappingKeyProvider]) -> None:
        self._providers = {provider.provider_id: provider for provider in providers}
        if not self._providers:
            raise ValueError("at least one key provider is required")

    def select_for_encryption(
        self,
        settings: EncryptionSettings,
        request: KeyRequest,
    ) -> KeyProviderSelection:
        primary = settings.key_reference
        if settings.provider_id is None or primary is None:
            raise KeyProviderInvalid("primary_key_provider_not_configured")
        if primary.provider_id != settings.provider_id:
            raise KeyProviderInvalid("primary_key_provider_mismatch")

        try:
            return self._select(primary, request, used_fallback=False)
        except KeyProviderUnavailable:
            fallback = settings.fallback_key_reference
            if fallback is None:
                raise
            if fallback.provider_id != "gpg":
                raise KeyProviderInvalid("fallback_provider_must_be_gpg") from None
            return self._select(fallback, request, used_fallback=True)

    def provider_for_handle(self, handle: KeyHandle) -> WrappingKeyProvider:
        provider = self._providers.get(handle.provider_id)
        if provider is None:
            raise KeyProviderUnavailable("key_provider_unavailable")
        health = provider.health_check()
        if health.state is KeyProviderState.LOCKED:
            raise KeyProviderLocked(health.code)
        if health.state is KeyProviderState.INVALID:
            raise KeyProviderInvalid(health.code)
        if not health.healthy:
            raise KeyProviderUnavailable(health.code)
        return provider

    def health_check(self, settings: EncryptionSettings) -> KeyProviderSelection:
        return self.select_for_encryption(
            settings,
            KeyRequest(
                purpose=KeyPurpose.RECORD,
                create_if_missing=False,
                reference=settings.key_reference.reference if settings.key_reference else None,
            ),
        )

    def _select(
        self,
        reference: CredentialReference,
        request: KeyRequest,
        *,
        used_fallback: bool,
    ) -> KeyProviderSelection:
        provider = self._providers.get(reference.provider_id)
        if provider is None:
            raise KeyProviderUnavailable("key_provider_unavailable")
        health = provider.health_check()
        if health.state is KeyProviderState.LOCKED:
            raise KeyProviderLocked(health.code)
        if health.state is KeyProviderState.INVALID:
            raise KeyProviderInvalid(health.code)
        if not health.healthy:
            raise KeyProviderUnavailable(health.code)
        key = provider.active_key(
            KeyRequest(
                purpose=request.purpose,
                create_if_missing=request.create_if_missing,
                reference=reference.reference,
            )
        )
        return KeyProviderSelection(provider=provider, key=key, used_fallback=used_fallback)
