from __future__ import annotations

from datetime import UTC, datetime, time, timedelta

import pytest
from pydantic import ValidationError

from local_recall.config import (
    CaptureRule,
    LocalRecallConfig,
    PolicyTimeWindow,
    PrivacyProfile,
    RuleEffect,
    RuleSettings,
)
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


def _provenance(
    source_id: str = "xorg-generic",
    *,
    observed_at: datetime = NOW,
) -> MetadataProvenance:
    return MetadataProvenance(
        source_id=source_id,
        observed_at=observed_at,
        confidence=SourceConfidence(0.95),
        adapter_revision="test-v1",
    )


def _metadata(
    values: dict[str, str | int | float | bool | None] | None = None,
    *,
    source_id: str = "xorg-generic",
    observed_at: datetime = NOW,
) -> ContextMetadata:
    values = values or {"application": "Editor", "workspace": "dev", "window.id": 7}
    provenance = _provenance(source_id, observed_at=observed_at)
    return ContextMetadata(
        observed_at=observed_at,
        fields=tuple(
            ContextField(name=name, value=value, provenance=(provenance,))
            for name, value in values.items()
        ),
    )


def _context(
    values: dict[str, str | int | float | bool | None] | None = None,
    *,
    source_id: str = "xorg-generic",
    evaluated_at: datetime = NOW,
    observed_at: datetime | None = None,
    full_screen: bool | None = None,
    generation: int = 1,
) -> PolicyEvaluationContext:
    observation = evaluated_at if observed_at is None else observed_at
    return PolicyEvaluationContext(
        metadata=_metadata(values, source_id=source_id, observed_at=observation),
        evaluated_at=evaluated_at,
        capture_generation=CaptureGeneration(generation),
        full_screen=full_screen,
    )


def _engine(
    *rules: CaptureRule,
    default: RuleEffect = RuleEffect.ALLOW,
    timezone: str = "UTC",
    sensitive_applications: tuple[str, ...] = (),
    sensitive_workspaces: tuple[str, ...] = (),
) -> PolicyEngine:
    config = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        rules=RuleSettings(
            default_effect=default,
            timezone=timezone,
            rules=rules,
            sensitive_applications=sensitive_applications,
            sensitive_workspaces=sensitive_workspaces,
        ),
    )
    return PolicyEngine(config, revision="policy-test-v1")


def _rule(
    rule_id: str,
    effect: RuleEffect,
    *,
    operations: tuple[PolicyOperation, ...] = (PolicyOperation.SCREENSHOT,),
    priority: int = 0,
    application: str | None = None,
    title_pattern: str | None = None,
    workspace: str | None = None,
    domain: str | None = None,
    include_subdomains: bool = False,
    full_screen: bool | None = None,
    metadata_source: str | None = None,
    time_window: PolicyTimeWindow | None = None,
) -> CaptureRule:
    return CaptureRule(
        rule_id=rule_id,
        effect=effect,
        operations=operations,
        priority=priority,
        application=application,
        title_pattern=title_pattern,
        workspace=workspace,
        domain=domain,
        include_subdomains=include_subdomains,
        full_screen=full_screen,
        metadata_source=metadata_source,
        time_window=time_window,
    )


def test_default_effect_respects_profile_policy() -> None:
    allowed = _engine(default=RuleEffect.ALLOW).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(),
    )
    denied = _engine(default=RuleEffect.DENY).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(),
    )

    assert allowed.allowed
    assert allowed.reason_code is PolicyReasonCode.DEFAULT_ALLOW
    assert not denied.allowed
    assert denied.reason_code is PolicyReasonCode.DEFAULT_DENY

    with pytest.raises(ValidationError):
        LocalRecallConfig(rules=RuleSettings(default_effect=RuleEffect.ALLOW))


def test_each_operation_is_gated_independently() -> None:
    rules = tuple(
        _rule(
            f"deny-{operation.value}",
            RuleEffect.DENY,
            operations=(operation,),
            application="Editor",
        )
        for operation in PolicyOperation
        if operation is not PolicyOperation.REMOTE_PROVIDER
    )
    policy = _engine(*rules)
    context = _context()

    for operation in PolicyOperation:
        phase = (
            PolicyPhase.PRE_CAPTURE
            if operation in {PolicyOperation.SCREENSHOT, PolicyOperation.METADATA}
            else PolicyPhase.DOWNSTREAM
        )
        decision = policy.evaluate(operation, phase, context)
        assert not decision.allowed
        if operation is PolicyOperation.REMOTE_PROVIDER:
            assert decision.reason_code is PolicyReasonCode.REMOTE_NOT_AUTHORIZED
        else:
            assert decision.rule_id == f"deny-{operation.value}"


def test_application_title_workspace_source_fullscreen_and_time_selectors() -> None:
    policy = _engine(
        _rule("app", RuleEffect.DENY, application="Editor"),
        _rule("title", RuleEffect.DENY, title_pattern="(?i)^secret", priority=1),
        _rule("workspace", RuleEffect.DENY, workspace="ops", priority=2),
        _rule("source", RuleEffect.DENY, metadata_source="qtile", priority=3),
        _rule("fullscreen", RuleEffect.DENY, full_screen=True, priority=4),
        _rule(
            "time",
            RuleEffect.DENY,
            time_window=PolicyTimeWindow(start=time(15, 0), end=time(17, 0)),
            priority=5,
        ),
    )
    context = _context(
        {
            "application": "Editor",
            "window.title": "SECRET plan",
            "workspace": "ops",
            "window.id": 9,
        },
        source_id="qtile",
        full_screen=True,
    )

    decision = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)

    assert not decision.allowed
    assert decision.rule_id == "time"


def test_explicit_deny_always_beats_allow_regardless_of_priority_or_order() -> None:
    deny = _rule("deny", RuleEffect.DENY, priority=-100, application="Editor")
    allow = _rule("allow", RuleEffect.ALLOW, priority=100, application="Editor")

    first = _engine(allow, deny).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(),
    )
    second = _engine(deny, allow).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(),
    )

    assert not first.allowed
    assert not second.allowed
    assert first.rule_id == second.rule_id == "deny"


def test_equal_priority_denies_are_stable_by_rule_identifier() -> None:
    first = _rule("z-deny", RuleEffect.DENY, application="Editor")
    second = _rule("a-deny", RuleEffect.DENY, application="Editor")
    policy = _engine(first, second)

    decision = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, _context())

    assert decision.rule_id == "a-deny"


def test_runtime_safety_state_beats_configured_allow() -> None:
    policy = _engine(_rule("allow", RuleEffect.ALLOW, application="Editor"))
    context = _context()

    policy.set_privacy_mode(True)
    privacy = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    assert not privacy.allowed
    assert privacy.reason_code is PolicyReasonCode.PRIVACY_MODE

    policy.set_privacy_mode(False)
    policy.set_session_locked(True)
    locked = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    assert not locked.allowed
    assert locked.reason_code is PolicyReasonCode.SESSION_LOCKED


def test_builtin_and_configured_sensitive_contexts_beat_default_allow() -> None:
    password_manager = _engine().evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": "KeePassXC", "workspace": "dev", "window.id": 1}),
    )
    configured_workspace = _engine(sensitive_workspaces=("pentest",)).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": "Terminal", "workspace": "pentest", "window.id": 2}),
    )
    configured_app = _engine(sensitive_applications=("CustomVault",)).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": "customvault", "workspace": "dev", "window.id": 3}),
    )

    assert not password_manager.allowed
    assert password_manager.reason_code is PolicyReasonCode.SENSITIVE_APPLICATION
    assert not configured_workspace.allowed
    assert configured_workspace.reason_code is PolicyReasonCode.SENSITIVE_WORKSPACE
    assert not configured_app.allowed
    assert configured_app.reason_code is PolicyReasonCode.SENSITIVE_APPLICATION


def test_authentication_title_is_builtin_sensitive_without_echoing_title() -> None:
    title = "Authentication Required — fake-password-DO-NOT-LEAK"
    policy = _engine()

    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": "Dialog", "window.title": title, "workspace": "dev"}),
    )

    assert not decision.allowed
    assert decision.reason_code is PolicyReasonCode.SENSITIVE_TITLE
    assert title not in repr(decision)


def test_domain_matching_exact_subdomain_suffix_case_and_trailing_dot() -> None:
    exact_policy = _engine(_rule("exact", RuleEffect.DENY, domain="Example.COM."))
    subdomain_policy = _engine(
        _rule("sub", RuleEffect.DENY, domain="example.com", include_subdomains=True)
    )
    exact_context = {
        "application": "Browser",
        "workspace": "web",
        "url.domain": "EXAMPLE.com",
    }
    sub_context = {
        "application": "Browser",
        "workspace": "web",
        "url.domain": "a.example.com",
    }

    exact = exact_policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(exact_context),
    )
    exact_sub = exact_policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(sub_context),
    )
    subdomain = subdomain_policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({**sub_context, "url.domain": "a.example.com."}),
    )
    suffix = subdomain_policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({**sub_context, "url.domain": "notexample.com"}),
    )

    assert not exact.allowed
    assert exact_sub.allowed
    assert not subdomain.allowed
    assert suffix.allowed


@pytest.mark.parametrize("domain", ["bad domain", "example", "-bad.example", "bad-.example"])
def test_malformed_configured_domains_are_rejected(domain: str) -> None:
    with pytest.raises(ValidationError):
        _rule("bad-domain", RuleEffect.DENY, domain=domain)


def test_ipv4_and_ipv6_domains_match_exactly() -> None:
    ipv4 = _engine(_rule("ipv4", RuleEffect.DENY, domain="127.0.0.1")).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(
            {"application": "Browser", "workspace": "web", "url.domain": "127.0.0.1"}
        ),
    )
    ipv6 = _engine(_rule("ipv6", RuleEffect.DENY, domain="2001:db8::1")).evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(
            {"application": "Browser", "workspace": "web", "url.domain": "2001:db8::1"}
        ),
    )

    assert not ipv4.allowed
    assert not ipv6.allowed


def test_time_windows_handle_midnight_and_configured_timezone() -> None:
    midnight = _engine(
        _rule(
            "night",
            RuleEffect.DENY,
            time_window=PolicyTimeWindow(start=time(23, 0), end=time(2, 0)),
        ),
        timezone="America/New_York",
    )
    inside = _context(evaluated_at=datetime(2026, 8, 13, 5, 0, tzinfo=UTC))
    outside = _context(evaluated_at=datetime(2026, 8, 13, 19, 0, tzinfo=UTC))

    assert not midnight.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        inside,
    ).allowed
    assert midnight.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        outside,
    ).allowed


def test_dst_transition_uses_aware_timestamp_and_configured_zone() -> None:
    policy = _engine(
        _rule(
            "dst-window",
            RuleEffect.DENY,
            time_window=PolicyTimeWindow(start=time(1, 0), end=time(2, 0)),
        ),
        timezone="America/New_York",
    )
    first_fold = _context(evaluated_at=datetime(2026, 11, 1, 5, 30, tzinfo=UTC))
    second_fold = _context(evaluated_at=datetime(2026, 11, 1, 6, 30, tzinfo=UTC))

    assert not policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        first_fold,
    ).allowed
    assert not policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        second_fold,
    ).allowed


def test_metadata_source_rules_use_normalized_provenance() -> None:
    policy = _engine(_rule("aw", RuleEffect.DENY, metadata_source="activitywatch"))

    denied = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(source_id="activitywatch"),
    )
    fallback = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(source_id="xorg-generic"),
    )

    assert not denied.allowed
    assert fallback.allowed


def test_missing_required_rule_context_fails_closed_uncertain() -> None:
    policy = _engine(_rule("needs-domain", RuleEffect.DENY, domain="example.com"))

    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": "Browser", "workspace": "web"}),
    )

    assert not decision.allowed
    assert not decision.certain
    assert decision.reason_code is PolicyReasonCode.REQUIRED_CONTEXT_MISSING
    assert decision.rule_id == "needs-domain"


def test_no_metadata_and_stale_metadata_fail_closed() -> None:
    policy = _engine()
    empty = PolicyEvaluationContext(
        metadata=ContextMetadata(observed_at=NOW, fields=()),
        evaluated_at=NOW,
        capture_generation=CaptureGeneration(1),
    )
    stale_at = NOW - timedelta(seconds=10)

    no_source = policy.evaluate(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, empty)
    stale = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(observed_at=stale_at),
    )

    assert not no_source.allowed
    assert no_source.reason_code is PolicyReasonCode.SOURCE_UNAVAILABLE
    assert not stale.allowed
    assert stale.reason_code is PolicyReasonCode.STALE_CONTEXT


def test_huge_metadata_value_fails_closed_without_echo() -> None:
    huge = "SENSITIVE" + "x" * 5000
    policy = _engine()

    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": huge, "workspace": "dev"}),
    )

    assert not decision.allowed
    assert not decision.certain
    assert decision.reason_code is PolicyReasonCode.MALFORMED_CONTEXT
    assert huge not in repr(decision)


@pytest.mark.parametrize(
    "pattern",
    [
        "(",
        "(a+)+$",
        "a|aa|aaa|aaaa",
        "(?=secret)secret",
        r"(secret)\1",
        "a" * 257,
    ],
)
def test_dangerous_or_oversized_title_patterns_are_rejected(pattern: str) -> None:
    with pytest.raises(ValidationError):
        _rule("bad-pattern", RuleEffect.DENY, title_pattern=pattern)


def test_unicode_title_pattern_remains_bounded_and_functional() -> None:
    policy = _engine(_rule("unicode", RuleEffect.DENY, title_pattern="秘密"))
    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": "Editor", "workspace": "dev", "window.title": "机密 秘密"}),
    )

    assert not decision.allowed


def test_temporary_window_and_workspace_sensitivity_expire_and_clear() -> None:
    policy = _engine()
    context = _context({"application": "Terminal", "workspace": "ops", "window.id": 42})

    policy.mark_current_sensitive(SensitiveScope.WINDOW, context, ttl_seconds=30)
    assert not policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context,
    ).allowed

    expired = PolicyEvaluationContext(
        metadata=context.metadata,
        evaluated_at=NOW + timedelta(seconds=31),
        capture_generation=context.capture_generation,
    )
    assert policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        expired,
    ).allowed

    policy.mark_current_sensitive(SensitiveScope.WORKSPACE, expired, ttl_seconds=30)
    assert not policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        expired,
    ).allowed
    policy.clear_temporary_sensitive(SensitiveScope.WORKSPACE)
    assert policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        expired,
    ).allowed


def test_temporary_sensitivity_does_not_cross_capture_generation() -> None:
    policy = _engine()
    original = _context({"application": "Terminal", "workspace": "ops", "window.id": 42})
    policy.mark_current_sensitive(SensitiveScope.WINDOW, original, ttl_seconds=60)
    next_session = _context(
        {"application": "Terminal", "workspace": "ops", "window.id": 42},
        generation=2,
    )

    assert policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        next_session,
    ).allowed


def test_privacy_lock_and_policy_reload_invalidate_authorization() -> None:
    context = _context()

    privacy = _engine()
    auth = privacy.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    privacy.set_privacy_mode(True)
    assert not privacy.is_authorization_current(auth)

    locked = _engine()
    auth = locked.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    locked.set_session_locked(True)
    assert not locked.is_authorization_current(auth)

    reloaded = _engine()
    auth = reloaded.authorize(PolicyOperation.SCREENSHOT, PolicyPhase.PRE_CAPTURE, context)
    replacement = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        rules=RuleSettings(default_effect=RuleEffect.DENY),
    )
    reloaded.replace_policy(replacement, revision="policy-test-v2")
    assert not reloaded.is_authorization_current(auth)


def test_policy_status_is_sanitized() -> None:
    secret = "sensitive-title-fake-bearer-token"
    policy = _engine(_rule("secret-title", RuleEffect.DENY, title_pattern=secret))

    status = policy.status()
    rendered = repr(status)

    assert status.enabled_rule_count == 1
    assert status.policy_revision == "policy-test-v1"
    assert secret not in rendered


def test_maximum_representative_rule_set_has_bounded_deterministic_result() -> None:
    rules = tuple(
        _rule(
            f"rule-{index:03d}",
            RuleEffect.DENY,
            application=f"App{index}",
        )
        for index in range(256)
    )
    policy = _engine(*rules)

    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context({"application": "App255", "workspace": "dev"}),
    )

    assert not decision.allowed
    assert decision.rule_id == "rule-255"
