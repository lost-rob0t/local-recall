from __future__ import annotations

from typing import Any

from .models import CredentialReference, LocalRecallConfig


def inspect_effective_configuration(configuration: LocalRecallConfig) -> dict[str, Any]:
    result = configuration.model_dump(mode="json")
    key_reference = configuration.encryption.key_reference
    result["encryption"]["key_reference"] = _inspect_reference(key_reference)
    result["encryption"]["gpg_recipient"] = (
        "<configured>" if configuration.encryption.gpg_recipient is not None else None
    )

    providers: list[dict[str, Any]] = []
    for provider in configuration.models.remote_providers:
        rendered = provider.model_dump(mode="json")
        rendered["credential_reference"] = _inspect_reference(provider.credential_reference)
        providers.append(rendered)
    result["models"]["remote_providers"] = providers

    rendered_allowlists: list[dict[str, Any]] = []
    for allowlist in configuration.redaction.allowlists:
        rendered_allowlists.append(
            {
                "allowlist_id": allowlist.allowlist_id,
                "pattern_id": allowlist.pattern_id,
                "exact_values": f"<configured:{len(allowlist.exact_values)}>",
            }
        )
    result["redaction"]["allowlists"] = rendered_allowlists
    return result


def _inspect_reference(reference: CredentialReference | None) -> dict[str, str] | None:
    if reference is None:
        return None
    return {
        "provider_id": reference.provider_id,
        "reference": "<configured>",
    }
