from __future__ import annotations

import ipaddress
import re
from datetime import time
from enum import StrEnum
from pathlib import PurePath
from typing import Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from local_recall.domain.policy import PolicyOperation

CURRENT_SCHEMA_VERSION = 1
MAX_POLICY_RULES = 256
MAX_POLICY_PATTERN_LENGTH = 256

_BUILTIN_REDACTION_PATTERN_IDS = frozenset(
    {
        "private-key",
        "authorization-header",
        "aws-access-key",
        "github-token",
        "slack-token",
        "stripe-secret",
        "google-api-key",
        "jwt",
        "password-assignment",
        "username-assignment",
        "generic-token-assignment",
        "credentialed-connection-string",
        "account-key-connection-string",
        "email-address",
        "high-entropy",
    }
)
_DEFAULT_POLICY_OPERATIONS = tuple(PolicyOperation)


class PrivacyProfile(StrEnum):
    PRIVACY_STRICT = "privacy-strict"
    LOCAL_ONLY = "local-only"
    LOCAL_FIRST = "local-first"


class RuleEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class CaptureOverloadPolicy(StrEnum):
    DROP_NEWEST = "drop-newest"
    COALESCE_LATEST = "coalesce-latest"


class IdleResumeBehavior(StrEnum):
    IMMEDIATE = "immediate"
    ACTIVE_GRACE = "active-grace"
    MANUAL = "manual"


class ActivityWatchURLMode(StrEnum):
    DISABLED = "disabled"
    DOMAIN_ONLY = "domain-only"


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)


class CredentialReference(FrozenModel):
    provider_id: str = Field(min_length=1, max_length=128)
    reference: str = Field(min_length=1, max_length=512, repr=False)


class PolicyTimeWindow(FrozenModel):
    start: time
    end: time

    @model_validator(mode="after")
    def reject_empty_window(self) -> PolicyTimeWindow:
        if self.start == self.end:
            raise ValueError("policy time window start and end must differ")
        if self.start.tzinfo is not None or self.end.tzinfo is not None:
            raise ValueError("policy time window values must be local wall-clock times")
        return self


class CaptureRule(FrozenModel):
    effect: RuleEffect
    rule_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    enabled: bool = True
    priority: int = Field(default=0, ge=-1000, le=1000)
    operations: tuple[PolicyOperation, ...] = _DEFAULT_POLICY_OPERATIONS
    application: str | None = Field(default=None, min_length=1, max_length=256)
    title_pattern: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_POLICY_PATTERN_LENGTH,
        repr=False,
    )
    workspace: str | None = Field(default=None, min_length=1, max_length=256)
    domain: str | None = Field(default=None, min_length=1, max_length=253, repr=False)
    include_subdomains: bool = False
    full_screen: bool | None = None
    metadata_source: str | None = Field(default=None, min_length=1, max_length=128)
    time_window: PolicyTimeWindow | None = None
    reason_code: str = Field(default="configured-rule", min_length=1, max_length=128)

    @field_validator("operations")
    @classmethod
    def validate_operations(
        cls,
        value: tuple[PolicyOperation, ...],
    ) -> tuple[PolicyOperation, ...]:
        if not value:
            raise ValueError("capture rule requires at least one operation")
        if len(set(value)) != len(value):
            raise ValueError("capture rule operations must be unique")
        return value

    @field_validator("title_pattern")
    @classmethod
    def validate_title_pattern(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("title_pattern must be a valid regular expression") from exc
        body = value[4:] if value.startswith("(?i)") else value
        if "(?" in body or "|" in body or "{" in body:
            raise ValueError("title_pattern uses an unsupported high-risk construct")
        if re.search(r"\\(?:[1-9]|g<)", body):
            raise ValueError("title_pattern backreferences are not supported")
        if re.search(r"\([^)]*[*+][^)]*\)[*+]", body):
            raise ValueError("title_pattern nested repetition is not supported")
        if body.count("*") + body.count("+") > 4:
            raise ValueError("title_pattern contains too many unbounded repetitions")
        return value

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().casefold().removesuffix(".")
        if not normalized:
            raise ValueError("policy domain is invalid")
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            labels = normalized.split(".")
            if len(labels) < 2:
                raise ValueError("policy domain is invalid") from None
            for label in labels:
                if not 1 <= len(label) <= 63:
                    raise ValueError("policy domain is invalid") from None
                if label[0] == "-" or label[-1] == "-":
                    raise ValueError("policy domain is invalid") from None
                if not all(
                    character.isascii() and (character.isalnum() or character == "-")
                    for character in label
                ):
                    raise ValueError("policy domain is invalid") from None
        return value

    @model_validator(mode="after")
    def require_selector(self) -> CaptureRule:
        selectors = (
            self.application,
            self.title_pattern,
            self.workspace,
            self.domain,
            self.full_screen,
            self.metadata_source,
            self.time_window,
        )
        if all(selector is None for selector in selectors):
            raise ValueError("capture rule requires at least one selector")
        if self.include_subdomains and self.domain is None:
            raise ValueError("include_subdomains requires a domain selector")
        return self


class RuleSettings(FrozenModel):
    default_effect: RuleEffect = RuleEffect.DENY
    timezone: str = Field(default="UTC", min_length=1, max_length=128)
    max_metadata_age_seconds: float = Field(default=5.0, gt=0.0, le=300.0)
    rules: tuple[CaptureRule, ...] = Field(default=(), max_length=MAX_POLICY_RULES)
    sensitive_applications: tuple[str, ...] = Field(default=(), max_length=64, repr=False)
    sensitive_workspaces: tuple[str, ...] = Field(default=(), max_length=64, repr=False)

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("policy timezone is unknown") from exc
        return value

    @field_validator("sensitive_applications", "sensitive_workspaces")
    @classmethod
    def validate_sensitive_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.strip() for item in value)
        if any(not item or len(item) > 256 for item in normalized):
            raise ValueError("sensitive-context values must be 1 to 256 characters")
        if len({item.casefold() for item in normalized}) != len(normalized):
            raise ValueError("sensitive-context values must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_rule_ids(self) -> RuleSettings:
        identifiers = tuple(rule.rule_id for rule in self.rules if rule.rule_id is not None)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("capture rule identifiers must be unique")
        return self


class IdleSettings(FrozenModel):
    enabled: bool = False
    pause_capture: bool = True
    threshold_seconds: float = Field(default=180.0, gt=0.0, le=86_400.0)
    resume_behavior: IdleResumeBehavior = IdleResumeBehavior.IMMEDIATE
    active_grace_seconds: float = Field(default=0.0, ge=0.0, le=300.0)
    max_observation_age_seconds: float = Field(default=5.0, gt=0.0, le=300.0)

    @model_validator(mode="after")
    def validate_resume_behavior(self) -> IdleSettings:
        if (
            self.resume_behavior is IdleResumeBehavior.ACTIVE_GRACE
            and self.active_grace_seconds <= 0.0
        ):
            raise ValueError("active-grace resume requires a positive grace period")
        if (
            self.resume_behavior is not IdleResumeBehavior.ACTIVE_GRACE
            and self.active_grace_seconds != 0.0
        ):
            raise ValueError("active grace is valid only with active-grace resume")
        return self


class CaptureSettings(FrozenModel):
    enabled: bool = False
    cadence_seconds: float = Field(default=15.0, ge=1.0, le=3600.0)
    screenshots_enabled: bool = True
    raw_queue_items: int = Field(default=1, ge=1, le=256)
    max_queue_items: int = Field(default=32, ge=1, le=256)
    overload_policy: CaptureOverloadPolicy = CaptureOverloadPolicy.DROP_NEWEST
    change_threshold: float = Field(default=0.02, ge=0.0, le=1.0)
    idle: IdleSettings = Field(default_factory=IdleSettings)


class ActivityWatchSettings(FrozenModel):
    endpoint: str = Field(
        default="http://127.0.0.1:5600",
        min_length=1,
        max_length=256,
    )
    connect_timeout_seconds: float = Field(default=0.25, gt=0.0, le=5.0)
    request_timeout_seconds: float = Field(default=0.75, gt=0.0, le=5.0)
    correlation_window_seconds: float = Field(default=2.0, gt=0.0, le=5.0)
    url_mode: ActivityWatchURLMode = ActivityWatchURLMode.DISABLED

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("ActivityWatch endpoint must be an HTTP loopback origin") from exc
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("ActivityWatch endpoint must be an HTTP loopback origin")
        return value


class MetadataSettings(FrozenModel):
    enabled_sources: tuple[str, ...] = ()
    window_titles_enabled: bool = False
    activitywatch: ActivityWatchSettings = Field(default_factory=ActivityWatchSettings)

    @field_validator("enabled_sources")
    @classmethod
    def validate_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(source.strip() for source in value)
        if any(not source for source in normalized):
            raise ValueError("metadata source identifiers must not be empty")
        if len(set(normalized)) != len(normalized):
            raise ValueError("metadata source identifiers must be unique")
        return normalized


class OCRSettings(FrozenModel):
    provider_id: Literal["tesseract-local"] = "tesseract-local"
    executable: str = Field(default="tesseract", min_length=1, max_length=4096)
    languages: tuple[str, ...] = ("eng",)
    timeout_seconds: float = Field(default=10.0, gt=0.0, le=120.0)
    max_input_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=1024,
        le=256 * 1024 * 1024,
    )

    @field_validator("executable")
    @classmethod
    def validate_executable(cls, value: str) -> str:
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("OCR executable path contains invalid characters")
        if PurePath(value).name != "tesseract":
            raise ValueError("OCR executable must resolve to the tesseract binary")
        return value

    @field_validator("languages")
    @classmethod
    def validate_languages(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("at least one OCR language is required")
        normalized = tuple(language.strip() for language in value)
        if any(not re.fullmatch(r"[A-Za-z0-9_+-]{1,32}", language) for language in normalized):
            raise ValueError("OCR language identifiers are invalid")
        if len(set(normalized)) != len(normalized):
            raise ValueError("OCR language identifiers must be unique")
        return normalized


class HighEntropySettings(FrozenModel):
    enabled: bool = True
    min_length: int = Field(default=20, ge=12, le=256)
    min_bits_per_character: float = Field(default=3.5, ge=2.0, le=6.0)
    hex_min_length: int = Field(default=32, ge=16, le=512)
    max_token_length: int = Field(default=512, ge=32, le=4096)

    @model_validator(mode="after")
    def validate_lengths(self) -> HighEntropySettings:
        if self.max_token_length < self.min_length:
            raise ValueError("max_token_length must be at least min_length")
        if self.max_token_length < self.hex_min_length:
            raise ValueError("max_token_length must be at least hex_min_length")
        return self


class CustomRedactionPattern(FrozenModel):
    pattern_id: str = Field(
        min_length=1,
        max_length=112,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    pattern: str = Field(min_length=1, max_length=2048, repr=False)

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("custom redaction pattern must be a valid regular expression") from exc
        return value


class RedactionAllowlist(FrozenModel):
    allowlist_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    )
    pattern_id: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_.:-]*$",
    )
    exact_values: tuple[str, ...] = Field(
        min_length=1,
        max_length=16,
        repr=False,
    )

    @field_validator("exact_values")
    @classmethod
    def validate_exact_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or len(item) > 256 for item in value):
            raise ValueError("allowlist values must be non-empty and at most 256 characters")
        if len(set(value)) != len(value):
            raise ValueError("allowlist values must be unique")
        return value


class RedactionSettings(FrozenModel):
    enabled: bool = True
    deterministic_required: bool = True
    fail_on_uncertain: bool = True
    model_assistance_enabled: bool = False
    policy_revision: str = Field(
        default="builtin-v1",
        pattern=r"^[A-Za-z0-9_.:-]{1,128}$",
    )
    low_confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    entropy: HighEntropySettings = HighEntropySettings()
    custom_patterns: tuple[CustomRedactionPattern, ...] = ()
    allowlists: tuple[RedactionAllowlist, ...] = ()

    @model_validator(mode="after")
    def validate_pattern_sets(self) -> RedactionSettings:
        pattern_ids = tuple(pattern.pattern_id for pattern in self.custom_patterns)
        if len(set(pattern_ids)) != len(pattern_ids):
            raise ValueError("custom redaction pattern identifiers must be unique")
        allowlist_ids = tuple(item.allowlist_id for item in self.allowlists)
        if len(set(allowlist_ids)) != len(allowlist_ids):
            raise ValueError("redaction allowlist identifiers must be unique")
        pairs = tuple((item.pattern_id, item.exact_values) for item in self.allowlists)
        if len(set(pairs)) != len(pairs):
            raise ValueError("duplicate redaction allowlists are not allowed")
        known_patterns = _BUILTIN_REDACTION_PATTERN_IDS | {
            f"custom:{pattern_id}" for pattern_id in pattern_ids
        }
        unknown_patterns = sorted({item.pattern_id for item in self.allowlists} - known_patterns)
        if unknown_patterns:
            raise ValueError("redaction allowlist references an unknown pattern")
        if self.model_assistance_enabled and not self.deterministic_required:
            raise ValueError("model-assisted redaction requires deterministic filters")
        return self


class RetentionSettings(FrozenModel):
    max_age_days: int = Field(default=30, ge=1, le=3650)
    max_bytes: int = Field(default=20 * 1024**3, ge=1024**2)
    max_records: int = Field(default=250_000, ge=1)


class RemoteProviderSettings(FrozenModel):
    provider_id: str = Field(min_length=1, max_length=128)
    enabled: bool = False
    kind: Literal["openai-compatible", "openrouter", "anthropic", "google"] | None = None
    endpoint: str | None = Field(default=None, min_length=1, max_length=2048, repr=False)
    model_id: str | None = Field(default=None, min_length=1, max_length=256)
    credential_reference: CredentialReference | None = None

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("remote provider endpoint must be a valid HTTPS URL") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith("/")
            or parsed.path == "/"
            or parsed.query
            or parsed.fragment
            or any(character in parsed.path for character in ("\x00", "\r", "\n"))
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("remote provider endpoint must be a valid HTTPS URL")
        return value

    @model_validator(mode="after")
    def require_executable_configuration(self) -> RemoteProviderSettings:
        if not self.enabled:
            return self
        missing = [
            name
            for name, value in (
                ("kind", self.kind),
                ("endpoint", self.endpoint),
                ("model_id", self.model_id),
                ("credential_reference", self.credential_reference),
            )
            if value is None
        ]
        if missing:
            raise ValueError("enabled remote provider requires " + ", ".join(missing))
        return self


class ModelSettings(FrozenModel):
    generation_provider: str = Field(
        default="ollama",
        min_length=1,
        max_length=128,
    )
    embedding_provider: str = Field(
        default="ollama",
        min_length=1,
        max_length=128,
    )
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
    algorithm: Literal["xchacha20-poly1305-ietf"] = "xchacha20-poly1305-ietf"
    fallback_provider_id: Literal["gpg"] | None = None
    gpg_recipient: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        repr=False,
    )
    gpg_executable: str = Field(
        default="gpg",
        min_length=1,
        max_length=4096,
    )
    gpg_timeout_seconds: float = Field(
        default=10.0,
        gt=0.0,
        le=120.0,
    )

    @field_validator("gpg_executable")
    @classmethod
    def validate_gpg_executable(cls, value: str) -> str:
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("GPG executable path contains invalid characters")
        if PurePath(value).name not in {"gpg", "gpg2"}:
            raise ValueError("GPG executable must resolve to gpg or gpg2")
        return value

    @model_validator(mode="after")
    def validate_fallback(self) -> EncryptionSettings:
        if self.fallback_provider_id is None:
            if self.gpg_recipient is not None:
                raise ValueError("gpg_recipient requires fallback_provider_id = gpg")
            return self
        if self.provider_id == self.fallback_provider_id:
            raise ValueError("encryption fallback provider must differ from primary provider")
        if self.gpg_recipient is None:
            raise ValueError("GPG fallback requires gpg_recipient")
        return self


class StorageSettings(FrozenModel):
    backend_id: str | None = Field(default=None, min_length=1, max_length=128)
    root_directory: str | None = Field(
        default=None,
        min_length=1,
        max_length=4096,
    )

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
    ocr: OCRSettings = OCRSettings()
    redaction: RedactionSettings = RedactionSettings()
    retention: RetentionSettings = RetentionSettings()
    models: ModelSettings = ModelSettings()
    encryption: EncryptionSettings = EncryptionSettings()
    storage: StorageSettings = StorageSettings()

    @model_validator(mode="after")
    def validate_security_invariants(self) -> LocalRecallConfig:
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {CURRENT_SCHEMA_VERSION}")

        local_profiles = {
            PrivacyProfile.PRIVACY_STRICT,
            PrivacyProfile.LOCAL_ONLY,
        }
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
