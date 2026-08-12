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

    rendered_rules: list[dict[str, Any]] = []
    for rule in configuration.rules.rules:
        rendered_rules.append(
            {
                "rule_id": rule.rule_id,
                "enabled": rule.enabled,
                "priority": rule.priority,
                "effect": rule.effect.value,
                "operations": [operation.value for operation in rule.operations],
                "application": "<configured>" if rule.application is not None else None,
                "title_pattern": "<configured>" if rule.title_pattern is not None else None,
                "workspace": "<configured>" if rule.workspace is not None else None,
                "domain": "<configured>" if rule.domain is not None else None,
                "include_subdomains": rule.include_subdomains,
                "full_screen": rule.full_screen,
                "metadata_source": (
                    "<configured>" if rule.metadata_source is not None else None
                ),
                "time_window": "<configured>" if rule.time_window is not None else None,
                "reason_code": rule.reason_code,
            }
        )
    result["rules"] = {
        "default_effect": configuration.rules.default_effect.value,
        "timezone": configuration.rules.timezone,
        "max_metadata_age_seconds": configuration.rules.max_metadata_age_seconds,
        "rules": rendered_rules,
        "sensitive_applications": (
            f"<configured:{len(configuration.rules.sensitive_applications)}>"
        ),
        "sensitive_workspaces": f"<configured:{len(configuration.rules.sensitive_workspaces)}>",
    }
    return result


def _inspect_reference(reference: CredentialReference | None) -> dict[str, str] | None:
    if reference is None:
        return None
    return {
        "provider_id": reference.provider_id,
        "reference": "<configured>",
    }
