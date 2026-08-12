from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ._validation import require_nonempty
from .lifecycle import CaptureGeneration


class PolicyOperation(StrEnum):
    SCREENSHOT = "screenshot"
    METADATA = "metadata"
    OCR = "ocr"
    INDEXING = "indexing"
    SUMMARIZATION = "summarization"
    REMOTE_PROVIDER = "remote-provider"


class PolicyPhase(StrEnum):
    PRE_CAPTURE = "pre-capture"
    POST_CAPTURE = "post-capture"
    DOWNSTREAM = "downstream"


class PolicyReasonCode(StrEnum):
    PRIVACY_MODE = "privacy-mode"
    SESSION_LOCKED = "session-locked"
    EXPLICIT_RULE_DENY = "explicit-rule-deny"
    EXPLICIT_RULE_ALLOW = "explicit-rule-allow"
    TEMPORARY_SENSITIVE_WINDOW = "temporary-sensitive-window"
    TEMPORARY_SENSITIVE_WORKSPACE = "temporary-sensitive-workspace"
    SENSITIVE_APPLICATION = "sensitive-application"
    SENSITIVE_TITLE = "sensitive-title"
    SENSITIVE_WORKSPACE = "sensitive-workspace"
    SENSITIVE_DOMAIN = "sensitive-domain"
    SOURCE_UNAVAILABLE = "source-unavailable"
    REQUIRED_CONTEXT_MISSING = "required-context-missing"
    MALFORMED_CONTEXT = "malformed-context"
    STALE_CONTEXT = "stale-context"
    POLICY_CONFLICT = "policy-conflict"
    DEFAULT_DENY = "default-deny"
    DEFAULT_ALLOW = "default-allow"
    REMOTE_NOT_AUTHORIZED = "remote-not-authorized"
    POLICY_UNAVAILABLE = "policy-unavailable"
    STALE_AUTHORIZATION = "stale-authorization"


class SensitiveScope(StrEnum):
    WINDOW = "window"
    WORKSPACE = "workspace"


@dataclass(frozen=True, slots=True, repr=False)
class PolicyDecision:
    operation: PolicyOperation
    phase: PolicyPhase
    allowed: bool
    certain: bool
    reason_code: PolicyReasonCode
    policy_revision: str
    policy_generation: int
    rule_id: str | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.policy_revision, "policy_revision")
        if self.policy_generation <= 0:
            raise ValueError("policy_generation must be positive")
        if self.rule_id is not None:
            require_nonempty(self.rule_id, "rule_id")

    def __repr__(self) -> str:
        return (
            "PolicyDecision("
            f"operation={self.operation.value!r}, phase={self.phase.value!r}, "
            f"allowed={self.allowed!r}, certain={self.certain!r}, "
            f"reason_code={self.reason_code.value!r}, rule_id={self.rule_id!r}, "
            f"policy_revision={self.policy_revision!r}, "
            f"policy_generation={self.policy_generation!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PolicyAuthorization:
    operation: PolicyOperation
    phase: PolicyPhase
    policy_revision: str
    policy_generation: int
    capture_generation: CaptureGeneration

    def __post_init__(self) -> None:
        require_nonempty(self.policy_revision, "policy_revision")
        if self.policy_generation <= 0:
            raise ValueError("policy_generation must be positive")

    def __repr__(self) -> str:
        return (
            "PolicyAuthorization("
            f"operation={self.operation.value!r}, phase={self.phase.value!r}, "
            f"policy_revision={self.policy_revision!r}, "
            f"policy_generation={self.policy_generation!r}, "
            f"capture_generation={int(self.capture_generation)!r})"
        )


@dataclass(frozen=True, slots=True)
class PolicyStatus:
    policy_revision: str
    policy_generation: int
    enabled_rule_count: int
    privacy_mode: bool
    session_locked: bool
    healthy: bool
    last_error_code: str | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.policy_revision, "policy_revision")
        if self.policy_generation <= 0:
            raise ValueError("policy_generation must be positive")
        if self.enabled_rule_count < 0:
            raise ValueError("enabled_rule_count must not be negative")
        if self.last_error_code is not None:
            require_nonempty(self.last_error_code, "last_error_code")
