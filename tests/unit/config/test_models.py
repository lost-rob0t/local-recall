from __future__ import annotations

import pytest
from pydantic import ValidationError

from local_recall.config import (
    CaptureRule,
    CaptureSettings,
    CredentialReference,
    EncryptionSettings,
    LocalRecallConfig,
    MetadataSettings,
    ModelSettings,
    PrivacyProfile,
    RedactionSettings,
    RemoteProviderSettings,
    RuleEffect,
    RuleSettings,
    StorageSettings,
)


def enabled_capture_config(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema_version": 1,
        "profile": "local-only",
        "capture": {"enabled": True},
        "metadata": {"enabled_sources": ["generic-xorg"]},
        "encryption": {
            "provider_id": "keyring",
            "key_reference": {"provider_id": "keyring", "reference": "record-key"},
        },
        "storage": {
            "backend_id": "sqlite-blobs",
            "root_directory": "/tmp/local-recall-test",
        },
    }
    data.update(overrides)
    return data


def test_safe_default_records_nothing() -> None:
    configuration = LocalRecallConfig.safe_default()

    assert configuration.profile is PrivacyProfile.PRIVACY_STRICT
    assert not configuration.capture.enabled
    assert not configuration.capture_permitted
    assert configuration.rules.default_effect is RuleEffect.DENY
    assert not configuration.models.remote_enabled


def test_capture_requires_complete_security_configuration() -> None:
    with pytest.raises(ValidationError, match="capture cannot start"):
        LocalRecallConfig(
            profile=PrivacyProfile.LOCAL_ONLY,
            capture=CaptureSettings(enabled=True),
        )


def test_complete_capture_configuration_is_permitted() -> None:
    configuration = LocalRecallConfig.model_validate(enabled_capture_config())

    assert configuration.capture_permitted


def test_privacy_strict_forbids_remote_providers() -> None:
    with pytest.raises(ValidationError, match="forbids remote providers"):
        LocalRecallConfig(
            profile=PrivacyProfile.PRIVACY_STRICT,
            models=ModelSettings(
                remote_enabled=True,
                remote_providers=(
                    RemoteProviderSettings(
                        provider_id="remote",
                        enabled=True,
                        credential_reference=CredentialReference(
                            provider_id="keyring",
                            reference="remote-api",
                        ),
                    ),
                ),
            ),
        )


def test_local_only_forbids_remote_providers() -> None:
    with pytest.raises(ValidationError, match="forbids remote providers"):
        LocalRecallConfig(
            profile=PrivacyProfile.LOCAL_ONLY,
            models=ModelSettings(
                remote_enabled=True,
                remote_providers=(
                    RemoteProviderSettings(
                        provider_id="remote",
                        enabled=True,
                        credential_reference=CredentialReference(
                            provider_id="keyring",
                            reference="remote-api",
                        ),
                    ),
                ),
            ),
        )


def test_local_first_allows_explicit_remote_provider() -> None:
    configuration = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        models=ModelSettings(
            remote_enabled=True,
            remote_providers=(
                RemoteProviderSettings(
                    provider_id="remote",
                    enabled=True,
                    credential_reference=CredentialReference(
                        provider_id="keyring",
                        reference="remote-api",
                    ),
                ),
            ),
        ),
    )

    assert configuration.models.remote_enabled


def test_remote_provider_is_disabled_by_default() -> None:
    configuration = LocalRecallConfig(profile=PrivacyProfile.LOCAL_FIRST)

    assert not configuration.models.remote_enabled
    assert configuration.models.remote_providers == ()


def test_capture_rules_require_selector_and_valid_regex() -> None:
    with pytest.raises(ValidationError, match="at least one selector"):
        CaptureRule(effect=RuleEffect.DENY)

    with pytest.raises(ValidationError, match="valid regular expression"):
        CaptureRule(effect=RuleEffect.DENY, title_pattern="[")


def test_capture_rules_cover_each_required_selector() -> None:
    rules = RuleSettings(
        rules=(
            CaptureRule(effect=RuleEffect.ALLOW, application="emacs"),
            CaptureRule(effect=RuleEffect.DENY, title_pattern="(?i)password"),
            CaptureRule(effect=RuleEffect.ALLOW, workspace="dev"),
            CaptureRule(effect=RuleEffect.DENY, metadata_source="untrusted"),
        )
    )

    assert len(rules.rules) == 4


def test_privacy_strict_requires_default_deny_and_deterministic_redaction() -> None:
    with pytest.raises(ValidationError, match="default deny"):
        LocalRecallConfig(rules=RuleSettings(default_effect=RuleEffect.ALLOW))

    with pytest.raises(ValidationError, match="model-assisted redaction"):
        LocalRecallConfig(redaction=RedactionSettings(model_assistance_enabled=True))


def test_enabled_capture_rejects_disabled_fail_closed_redaction() -> None:
    data = enabled_capture_config(
        redaction={
            "enabled": True,
            "deterministic_required": True,
            "fail_on_uncertain": False,
        }
    )

    with pytest.raises(ValidationError, match="fail_on_uncertain"):
        LocalRecallConfig.model_validate(data)


def test_secret_fields_are_not_part_of_schema() -> None:
    data = enabled_capture_config()
    data["models"] = {"api_key": "should-never-be-accepted"}

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LocalRecallConfig.model_validate(data)


def test_models_are_frozen() -> None:
    configuration = LocalRecallConfig()

    with pytest.raises(ValidationError, match="frozen"):
        configuration.capture = CaptureSettings(enabled=False)


def test_explicit_settings_are_represented() -> None:
    configuration = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_ONLY,
        metadata=MetadataSettings(enabled_sources=("generic-xorg",)),
        encryption=EncryptionSettings(provider_id="keyring"),
        storage=StorageSettings(backend_id="sqlite-blobs"),
    )

    assert configuration.metadata.enabled_sources == ("generic-xorg",)
