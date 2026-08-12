from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.audit.errors import AuditFailure
from local_recall.audit.models import (
    AuditAction,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditReasonCode,
)
from local_recall.config import (
    ConfigurationLoadError,
    ConfigurationManager,
    LocalRecallConfig,
    PrivacyProfile,
    RuleEffect,
    RuleSettings,
    inspect_effective_configuration,
)
from local_recall.config.loader import load_configuration_mapping
from local_recall.config.models import CaptureRule
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.policy import PolicyOperation, PolicyPhase
from local_recall.policy import PolicyEngine, PolicyEvaluationContext

NOW = datetime(2026, 8, 12, 18, 0, tzinfo=UTC)
SECRETS = (
    "FakePassword-DoNotLeak-47!",
    "Bearer fake-token-abcdef123456",
    "person@example.invalid",
    "synthetic-user",
    "Sensitive payroll title",
    "vault.example.invalid",
    "sudo synthetic-command --token fake",
    "Authentication Required FakePassword-DoNotLeak-47!",
)


def _context(title: str = SECRETS[-1]) -> PolicyEvaluationContext:
    provenance = MetadataProvenance(
        source_id="xorg-generic",
        observed_at=NOW,
        confidence=SourceConfidence(0.9),
    )
    metadata = ContextMetadata(
        observed_at=NOW,
        fields=(
            ContextField(name="application", value="Dialog", provenance=(provenance,)),
            ContextField(name="window.title", value=title, provenance=(provenance,)),
            ContextField(name="workspace", value="dev", provenance=(provenance,)),
        ),
    )
    return PolicyEvaluationContext(
        metadata=metadata,
        evaluated_at=NOW,
        capture_generation=CaptureGeneration(1),
    )


def _engine(rule: CaptureRule | None = None) -> PolicyEngine:
    rules = () if rule is None else (rule,)
    configuration = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        rules=RuleSettings(default_effect=RuleEffect.ALLOW, rules=rules),
    )
    return PolicyEngine(configuration, revision="security-policy-v1")


def test_sensitive_match_values_never_appear_in_decision_status_or_exception() -> None:
    engine = _engine()
    context = _context()
    decision = engine.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)

    with pytest.raises(PermissionError) as raised:
        engine.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)

    rendered = " ".join((repr(decision), repr(engine.status()), str(raised.value)))
    for secret in SECRETS:
        assert secret not in rendered


def test_effective_configuration_hides_policy_matcher_values() -> None:
    sensitive_title = "Sensitive payroll title"
    sensitive_domain = "vault.example.invalid"
    configuration = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        rules=RuleSettings(
            default_effect=RuleEffect.ALLOW,
            sensitive_applications=("PrivateVault",),
            sensitive_workspaces=("pentest",),
            rules=(
                CaptureRule(
                    rule_id="secret-rule",
                    effect=RuleEffect.DENY,
                    title_pattern=sensitive_title,
                    domain=sensitive_domain,
                ),
            ),
        ),
    )

    rendered = repr(inspect_effective_configuration(configuration))

    assert "secret-rule" in rendered
    assert sensitive_title not in rendered
    assert sensitive_domain not in rendered
    assert "PrivateVault" not in rendered
    assert "pentest" not in rendered


def test_invalid_policy_config_error_does_not_echo_secret_input() -> None:
    secret = "FakePassword-DoNotLeak-47!"  # pragma: allowlist secret
    with pytest.raises(ConfigurationLoadError) as raised:
        load_configuration_mapping(
            {
                "schema_version": 1,
                "rules": {
                    "rules": [
                        {
                            "effect": "deny",
                            "title_pattern": f"({secret}",
                        }
                    ]
                },
            }
        )

    assert secret not in str(raised.value)


def test_extra_policy_configuration_fields_are_rejected() -> None:
    with pytest.raises(ConfigurationLoadError):
        load_configuration_mapping(
            {
                "schema_version": 1,
                "rules": {
                    "rules": [
                        {
                            "effect": "deny",
                            "application": "Editor",
                            "unknown_policy_key": True,
                        }
                    ]
                },
            }
        )


def test_malformed_policy_reload_fails_to_safe_default() -> None:
    manager = ConfigurationManager()
    valid = manager.reload_mapping(
        {
            "schema_version": 1,
            "profile": "local-first",
            "rules": {"default_effect": "allow"},
        }
    )
    assert valid.accepted

    rejected = manager.reload_mapping(
        {
            "schema_version": 1,
            "profile": "local-first",
            "rules": {
                "default_effect": "allow",
                "rules": [{"effect": "deny", "title_pattern": "(a+)+$"}],
            },
        }
    )

    assert not rejected.accepted
    assert rejected.snapshot.configuration == LocalRecallConfig.safe_default()
    assert rejected.snapshot.configuration.rules.default_effect is RuleEffect.DENY


def test_audit_event_cannot_carry_policy_match_content() -> None:
    event = AuditEvent(
        category=AuditCategory.POLICY,
        action=AuditAction.POLICY_DECISION,
        outcome=AuditOutcome.REJECTED,
        reason=AuditReasonCode.POLICY_DENY,
        correlation_id=uuid4(),
        occurred_at=NOW,
        generation=1,
    )

    rendered = repr(event)
    for secret in SECRETS:
        assert secret not in rendered

    with pytest.raises(AuditFailure):
        AuditEvent(
            category=AuditCategory.POLICY,
            action=AuditAction.POLICY_DECISION,
            outcome=AuditOutcome.REJECTED,
            reason=AuditReasonCode.POLICY_DENY,
            correlation_id=uuid4(),
            occurred_at=NOW,
            generation=1,
            attributes={"window_title": 1},
        )


def test_stale_authorization_is_invalidated_by_privacy_lock_and_revision() -> None:
    context = _context("Normal title")

    privacy = _engine()
    authorization = privacy.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    privacy.set_privacy_mode(True)
    assert not privacy.is_authorization_current(authorization)

    locked = _engine()
    authorization = locked.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    locked.set_session_locked(True)
    assert not locked.is_authorization_current(authorization)

    reloaded = _engine()
    authorization = reloaded.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    replacement = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        rules=RuleSettings(default_effect=RuleEffect.DENY),
    )
    reloaded.replace_policy(replacement, revision="security-policy-v2")
    assert not reloaded.is_authorization_current(authorization)


def test_remote_provider_stays_denied_without_explicit_profile_authorization() -> None:
    engine = _engine()

    decision = engine.evaluate(
        PolicyOperation.REMOTE_PROVIDER,
        PolicyPhase.DOWNSTREAM,
        _context("Normal title"),
    )

    assert not decision.allowed
    assert decision.reason_code.value == "remote-not-authorized"


def test_policy_domain_objects_cannot_carry_pixels_or_ocr_content() -> None:
    from local_recall.domain.policy import PolicyAuthorization, PolicyDecision

    decision_fields = set(PolicyDecision.__dataclass_fields__)
    authorization_fields = set(PolicyAuthorization.__dataclass_fields__)

    forbidden = {"pixels", "screenshot", "ocr", "ocr_text", "window_title", "domain"}
    assert decision_fields.isdisjoint(forbidden)
    assert authorization_fields.isdisjoint(forbidden)


def test_policy_modules_have_no_capture_storage_redaction_or_provider_side_effect_imports() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "local_recall" / "policy"
    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(root.glob("*.py")))
    forbidden_imports = (
        "local_recall.storage",
        "local_recall.providers",
        "local_recall.redaction",
        "PIL.ImageGrab",
        "mss",
        "requests.",
        "httpx.",
    )

    for forbidden in forbidden_imports:
        assert forbidden not in source
