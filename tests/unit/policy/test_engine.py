from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from local_recall.config.models import CaptureRule, LocalRecallConfig, RuleEffect, RuleSettings
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import (
    ContextField,
    ContextMetadata,
    MetadataProvenance,
    SourceConfidence,
)
from local_recall.domain.policy import (
    PolicyOperation,
    PolicyPhase,
    PolicyReasonCode,
    SensitiveScope,
)
from local_recall.policy import PolicyEngine, PolicyEvaluationContext

NOW = datetime(2026, 8, 12, 16, 0, tzinfo=UTC)


def provenance(source_id: str = "xorg-generic") -> MetadataProvenance:
    return MetadataProvenance(
        source_id=source_id,
        observed_at=NOW,
        confidence=SourceConfidence(0.99),
        adapter_revision="test-v1",
    )


def metadata(**values: str | int | float | bool | None) -> ContextMetadata:
    fields = tuple(
        ContextField(name=name, value=value, provenance=(provenance(),))
        for name, value in values.items()
    )
    return ContextMetadata(observed_at=NOW, fields=fields)


def context(
    data: ContextMetadata | None = None,
    *,
    now: datetime = NOW,
    full_screen: bool | None = None,
    generation: int = 1,
) -> PolicyEvaluationContext:
    return PolicyEvaluationContext(
        metadata=data or metadata(application="Editor", workspace="work"),
        evaluated_at=now,
        capture_generation=CaptureGeneration(generation),
        full_screen=full_screen,
    )


def engine(*rules: CaptureRule, default: RuleEffect = RuleEffect.DENY) -> PolicyEngine:
    configuration = LocalRecallConfig(rules=RuleSettings(default_effect=default, rules=rules))
    return PolicyEngine(configuration, revision="policy-revision-1")


def test_explicit_application_allow_and_deny_are_operation_specific() -> None:
    policy = engine(
        CaptureRule(
            rule_id="allow-editor-metadata",
            effect=RuleEffect.ALLOW,
            operations=(PolicyOperation.METADATA,),
            application="Editor",
        ),
        CaptureRule(
            rule_id="deny-editor-screenshot",
            effect=RuleEffect.DENY,
            operations=(PolicyOperation.SCREENSHOT,),
            application="Editor",
        ),
    )
    ctx = context()

    screenshot = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx)
    metadata_capture = policy.evaluate(PolicyOperation.METADATA, PolicyPhase.PRE_CAPTURE, ctx)

    assert not screenshot.allowed
    assert screenshot.rule_id == "deny-editor-screenshot"
    assert screenshot.reason_code is PolicyReasonCode.EXPLICIT_RULE_DENY
    assert metadata_capture.allowed
    assert metadata_capture.rule_id == "allow-editor-metadata"


def test_privacy_mode_and_lock_override_configured_allow() -> None:
    policy = engine(
        CaptureRule(
            rule_id="allow-editor",
            effect=RuleEffect.ALLOW,
            operations=(PolicyOperation.SCREENSHOT,),
            application="Editor",
        )
    )
    ctx = context()

    policy.set_privacy_mode(True)
    privacy = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx)
    assert not privacy.allowed
    assert privacy.reason_code is PolicyReasonCode.PRIVACY_MODE

    policy.set_privacy_mode(False)
    policy.set_session_locked(True)
    locked = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx)
    assert not locked.allowed
    assert locked.reason_code is PolicyReasonCode.SESSION_LOCKED


def test_builtin_password_manager_deny_beats_default_allow() -> None:
    policy = engine(default=RuleEffect.ALLOW)
    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context(metadata(application="KeePassXC", workspace="work")),
    )

    assert not decision.allowed
    assert decision.reason_code is PolicyReasonCode.SENSITIVE_APPLICATION
    assert decision.rule_id is not None


def test_missing_policy_relevant_context_fails_closed_for_screenshot() -> None:
    policy = engine(
        CaptureRule(
            rule_id="deny-secret-domain",
            effect=RuleEffect.DENY,
            operations=(PolicyOperation.SCREENSHOT,),
            domain="secret.example",
        ),
        default=RuleEffect.ALLOW,
    )
    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context(metadata(application="Browser", workspace="web")),
    )

    assert not decision.allowed
    assert not decision.certain
    assert decision.reason_code is PolicyReasonCode.REQUIRED_CONTEXT_MISSING
    assert decision.rule_id == "deny-secret-domain"


def test_domain_subdomain_matching_does_not_have_suffix_confusion() -> None:
    policy = engine(
        CaptureRule(
            rule_id="deny-example",
            effect=RuleEffect.DENY,
            operations=(PolicyOperation.SCREENSHOT,),
            domain="example.com",
            include_subdomains=True,
        ),
        default=RuleEffect.ALLOW,
    )

    exact = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context(metadata(application="Browser", workspace="web", **{"url.domain": "EXAMPLE.COM"})),
    )
    subdomain = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context(metadata(application="Browser", workspace="web", **{"url.domain": "a.example.com"})),
    )
    suffix = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context(metadata(application="Browser", workspace="web", **{"url.domain": "notexample.com"})),
    )

    assert not exact.allowed
    assert not subdomain.allowed
    assert suffix.allowed


def test_temporary_sensitive_context_invalidates_old_authorization() -> None:
    policy = engine(default=RuleEffect.ALLOW)
    ctx = context(metadata(application="Terminal", workspace="ops", **{"window.id": 42}))
    authorization = policy.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx)

    policy.mark_current_sensitive(SensitiveScope.WINDOW, ctx, ttl_seconds=60)

    assert not policy.is_authorization_current(authorization)
    decision = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx)
    assert not decision.allowed
    assert decision.reason_code is PolicyReasonCode.TEMPORARY_SENSITIVE_WINDOW


def test_temporary_sensitive_context_expires_deterministically() -> None:
    policy = engine(default=RuleEffect.ALLOW)
    ctx = context(metadata(application="Editor", workspace="sensitive"))
    policy.mark_current_sensitive(SensitiveScope.WORKSPACE, ctx, ttl_seconds=30)

    assert not policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx).allowed

    later = context(ctx.metadata, now=NOW + timedelta(seconds=31))
    assert policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, later).allowed


def test_policy_reload_invalidates_old_authorization() -> None:
    policy = engine(default=RuleEffect.ALLOW)
    ctx = context()
    authorization = policy.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx)

    policy.replace_policy(
        LocalRecallConfig(rules=RuleSettings(default_effect=RuleEffect.DENY)),
        revision="policy-revision-2",
    )

    assert not policy.is_authorization_current(authorization)
    assert not policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx).allowed


def test_remote_eligibility_is_independent_and_denied_by_default() -> None:
    policy = engine(default=RuleEffect.ALLOW)
    ctx = context()

    screenshot = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, ctx)
    remote = policy.evaluate(
        PolicyOperation.REMOTE_PROVIDER,
        PolicyPhase.DOWNSTREAM,
        ctx,
    )

    assert screenshot.allowed
    assert not remote.allowed
    assert remote.reason_code is PolicyReasonCode.REMOTE_NOT_AUTHORIZED


def test_equal_priority_conflict_is_deterministically_deny() -> None:
    policy = engine(
        CaptureRule(
            rule_id="z-allow",
            priority=10,
            effect=RuleEffect.ALLOW,
            operations=(PolicyOperation.SCREENSHOT,),
            application="Editor",
        ),
        CaptureRule(
            rule_id="a-deny",
            priority=10,
            effect=RuleEffect.DENY,
            operations=(PolicyOperation.SCREENSHOT,),
            application="Editor",
        ),
        default=RuleEffect.ALLOW,
    )

    decision = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context())

    assert not decision.allowed
    assert decision.rule_id == "a-deny"
    assert decision.reason_code is PolicyReasonCode.EXPLICIT_RULE_DENY


def test_stale_metadata_fails_closed_without_echoing_sensitive_values() -> None:
    secret_title = "AUTH DIALOG fake-password-DO-NOT-LEAK"
    stale_time = NOW - timedelta(minutes=1)
    stale_provenance = MetadataProvenance(
        source_id="xorg-generic",
        observed_at=stale_time,
        confidence=SourceConfidence(0.9),
    )
    data = ContextMetadata(
        observed_at=stale_time,
        fields=(
            ContextField(
                name="window.title",
                value=secret_title,
                provenance=(stale_provenance,),
            ),
        ),
    )
    policy = engine(default=RuleEffect.ALLOW)

    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context(data),
    )

    assert not decision.allowed
    assert not decision.certain
    rendered = repr(decision)
    assert secret_title not in rendered
    assert "fake-password" not in rendered


def test_invalid_or_pathological_title_patterns_are_rejected_at_configuration_boundary() -> None:
    bad_patterns = ("(", "(a+)+$", "a|aa|aaa|aaaa", "a" * 513)
    for pattern in bad_patterns:
        with pytest.raises(ValueError):
            CaptureRule(
                rule_id="bad-pattern",
                effect=RuleEffect.DENY,
                title_pattern=pattern,
            )
