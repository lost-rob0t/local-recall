from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CURRENT_SCHEMA_VERSION = 1


class PrivacyProfile(StrEnum):
    PRIVACY_STRICT = "privacy-strict"
    LOCAL_ONLY = "local-only"
    LOCAL_FIRST = "local-first"


class RuleEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)


class CredentialReference(FrozenModel):
    provider_id: str = Field(min_length=1, max_length=128)
    reference: str = Field(min_length=1, max_length=512, repr=False)


class CaptureRule(FrozenModel):
    effect: RuleEffect
    application: str | None = Field(default=None, min_length=1, max_length=256)
    title_pattern: str | None = Field(default=None, min_length=1, max_length=512)
    workspace: str | None = Field(default=None, min_length=1, max_length=256)
    metadata_source: str | None = Field(default=None, min_length=1, max_length=128)
    reason_code: str = Field(default="configured-rule", min_length=1, max_length=128)

    @field_validator("title_pattern")
    @classmethod
    def validate_title_pattern(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError("title_pattern must be a valid regular expression") from exc
        return value

    @model_validator(mode="after")
    def require_selector(self) -> CaptureRule:
        selectors = (
            self.application,
            self.title_pattern,
            self.workspace,
            self.metadata_source,
        )
        if all(selector is None for selector in selectors):
            raise ValueError("capture rule requires at least one selector")
        return self


class RuleSettings(FrozenModel):
    default_effect: RuleEffect = RuleEffect.DENY
    rules: tuple[CaptureRule, ...] = ()


class CaptureSettings(FrozenModel):
    enabled: bool = False
    cadence_seconds: float = Field(default=15.0, ge=1.0, le=3600.0)
    screenshots_enabled: bool = True
    max_queue_items: int = Field(default=32, ge=1, le=256)
    change_threshold: float = Field(default=0.02, ge=0.0, le=1.0)


class MetadataSettings(FrozenModel):
    enabled_sources: tuple[str, ...] = ()

    @field_validator("enabled_sources")
    @classmethod
    def validate_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(source.strip() for source in value)
        if any(not source for source in normalized):
            raise ValueError("metadata source identifiers must not be empty")
        if len(set(normalized)) != len(normalized):
            raise ValueError("metadata source identifiers must be unique")
        return normalized


class RedactionSettings(FrozenModel):
    enabled: bool = True
    deterministic_required: bool = True
    fail_on_uncertain: bool = True
    model_assistance_enabled: bool = False
    policy_revision: str = Field(default="builtin-v1", min_length=1, max_length=128)


class RetentionSettings(FrozenModel):
    max_age_days: int = Field(default=30, ge=1, le=3650)
    max_bytes: int = Field(default=20 * 1024**3, ge=1024**2)
    max_records: int = Field(default=250_000, ge=1)


class RemoteProviderSettings(FrozenModel):
    provider_id: str = Field(min_length=1, max_length=128)
    enabled: bool = False
    credential_reference: CredentialReference | None = None

    @model_validator(mode="after")
    def require_credential_reference(self) -> RemoteProviderSettings:
        if self.enabled and self.credential_reference is None:
            raise ValueError("enabled remote provider requires credential_reference")
        return self


class ModelSettings(FrozenModel):
    generation_provider: str = Field(default="ollama", min_length=1, max_length=128)
    embedding_provider: str = Field(default="ollama", min_length=1, max_length=128)
    remote_enabled: bool = False
    remote_providers: tuple[RemoteProviderSettings, ...] = ()

    @model_validator(mode="after")
    def validate_remote_provider_set(self) -> ModelSettings:
        identifiers = tuple(provider.provider_id for provider in self.remote_providers)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("remote provider identifiers must be unique")
        if self.remote_enabled and not any(provider.enabled for provider in self.remote_providers):
            raise ValueError("remote_enabled requires at least one enabled remote provider")
        if not self.remote_enabled and any(provider.enabled for provider in self.remote_providers):
            raise ValueError("enabled remote providers require remote_enabled")
        return self


class EncryptionSettings(FrozenModel):
    provider_id: str | None = Field(default=None, min_length=1, max_length=128)
    key_reference: CredentialReference | None = None
    algorithm: str = Field(default="xchacha20-poly1305", min_length=1, max_length=128)


class StorageSettings(FrozenModel):
    backend_id: str | None = Field(default=None, min_length=1, max_length=128)
    root_directory: str | None = Field(default=None, min_length=1, max_length=4096)

    @field_validator("root_directory")
    @classmethod
    def validate_root_directory(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("root_directory must not contain NUL bytes")
        return value


class LocalRecallConfig(FrozenModel):
    schema_version: int = CURRENT_SCHEMA_VERSION
    profile: PrivacyProfile = PrivacyProfile.PRIVACY_STRICT
    capture: CaptureSettings = CaptureSettings()
    rules: RuleSettings = RuleSettings()
    metadata: MetadataSettings = MetadataSettings()
    redaction: RedactionSettings = RedactionSettings()
    retention: RetentionSettings = RetentionSettings()
    models: ModelSettings = ModelSettings()
    encryption: EncryptionSettings = EncryptionSettings()
    storage: StorageSettings = StorageSettings()

    @model_validator(mode="after")
    def validate_security_invariants(self) -> LocalRecallConfig:
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {CURRENT_SCHEMA_VERSION}")

        local_profiles = {PrivacyProfile.PRIVACY_STRICT, PrivacyProfile.LOCAL_ONLY}
        if self.profile in local_profiles and self.models.remote_enabled:
            raise ValueError(f"profile {self.profile.value} forbids remote providers")

        if self.profile is PrivacyProfile.PRIVACY_STRICT:
            if self.rules.default_effect is not RuleEffect.DENY:
                raise ValueError("privacy-strict requires default deny capture rules")
            if self.redaction.model_assistance_enabled:
                raise ValueError("privacy-strict forbids model-assisted redaction")

        if self.capture.enabled:
            missing: list[str] = []
            if not self.metadata.enabled_sources:
                missing.append("metadata.enabled_sources")
            if not self.redaction.enabled:
                missing.append("redaction.enabled")
            if not self.redaction.deterministic_required:
                missing.append("redaction.deterministic_required")
            if not self.redaction.fail_on_uncertain:
                missing.append("redaction.fail_on_uncertain")
            if self.encryption.provider_id is None:
                missing.append("encryption.provider_id")
            if self.encryption.key_reference is None:
                missing.append("encryption.key_reference")
            if self.storage.backend_id is None:
                missing.append("storage.backend_id")
            if self.storage.root_directory is None:
                missing.append("storage.root_directory")
            if missing:
                joined = ", ".join(missing)
                raise ValueError(f"capture cannot start; missing security configuration: {joined}")
        return self

    @property
    def capture_permitted(self) -> bool:
        return self.capture.enabled

    @classmethod
    def safe_default(cls) -> LocalRecallConfig:
        return cls()
