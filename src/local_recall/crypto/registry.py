from __future__ import annotations

from dataclasses import dataclass

from local_recall.domain.crypto import KeyRequest
from local_recall.ports.keys import KeyHealthStatus, KeyProvider

from .errors import KeyProviderFailure, KeyProviderFailureCode


@dataclass(frozen=True, slots=True)
class KeyProviderSelection:
    provider: KeyProvider
    used_explicit_fallback: bool


class KeyProviderRegistry:
    def __init__(self, providers: tuple[KeyProvider, ...]) -> None:
        mapping: dict[str, KeyProvider] = {}
        for provider in providers:
            if provider.provider_id in mapping:
                raise ValueError(f"duplicate key provider: {provider.provider_id}")
            mapping[provider.provider_id] = provider
        self._providers = mapping

    async def select(
        self,
        primary_provider_id: str,
        request: KeyRequest,
        *,
        explicit_fallback_provider_id: str | None = None,
    ) -> KeyProviderSelection:
        primary = self._require_provider(primary_provider_id)
        primary_health = await primary.health(request)
        if primary_health.ready:
            return KeyProviderSelection(primary, used_explicit_fallback=False)

        if explicit_fallback_provider_id is None:
            raise KeyProviderFailure(
                primary_provider_id,
                _failure_code(primary_health.status),
            )
        if explicit_fallback_provider_id == primary_provider_id:
            raise KeyProviderFailure(
                primary_provider_id, KeyProviderFailureCode.INVALID_KEY
            )

        fallback = self._require_provider(explicit_fallback_provider_id)
        fallback_health = await fallback.health(request)
        if not fallback_health.ready:
            raise KeyProviderFailure(
                explicit_fallback_provider_id,
                _failure_code(fallback_health.status),
            )
        return KeyProviderSelection(fallback, used_explicit_fallback=True)

    def _require_provider(self, provider_id: str) -> KeyProvider:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise KeyProviderFailure(
                provider_id, KeyProviderFailureCode.PROVIDER_UNAVAILABLE
            ) from exc


def _failure_code(status: KeyHealthStatus) -> KeyProviderFailureCode:
    return {
        KeyHealthStatus.LOCKED: KeyProviderFailureCode.KEY_LOCKED,
        KeyHealthStatus.INVALID: KeyProviderFailureCode.INVALID_KEY,
        KeyHealthStatus.REVOKED: KeyProviderFailureCode.REVOKED,
    }.get(status, KeyProviderFailureCode.PROVIDER_UNAVAILABLE)
