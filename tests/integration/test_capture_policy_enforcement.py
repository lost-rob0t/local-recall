from __future__ import annotations

from datetime import UTC, datetime

import pytest

from local_recall.config import (
    CaptureRule,
    LocalRecallConfig,
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
from local_recall.domain.policy import PolicyOperation, PolicyPhase
from local_recall.policy import PolicyEnforcementBoundary, PolicyEngine, PolicyEvaluationContext

NOW = datetime(2026, 8, 12, 17, 0, tzinfo=UTC)


def _context(
    *,
    application: str = "Editor",
    workspace: str = "dev",
    source_id: str = "xorg-generic",
) -> PolicyEvaluationContext:
    provenance = MetadataProvenance(
        source_id=source_id,
        observed_at=NOW,
        confidence=SourceConfidence(0.95),
        adapter_revision="synthetic-v1",
    )
    metadata = ContextMetadata(
        observed_at=NOW,
        fields=(
            ContextField(name="application", value=application, provenance=(provenance,)),
            ContextField(name="workspace", value=workspace, provenance=(provenance,)),
            ContextField(name="window.id", value=7, provenance=(provenance,)),
        ),
    )
    return PolicyEvaluationContext(
        metadata=metadata,
        evaluated_at=NOW,
        capture_generation=CaptureGeneration(1),
    )


def _engine(*rules: CaptureRule, default: RuleEffect = RuleEffect.ALLOW) -> PolicyEngine:
    configuration = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        rules=RuleSettings(default_effect=default, rules=rules),
    )
    return PolicyEngine(configuration, revision="integration-policy-v1")


def _rule(
    rule_id: str,
    effect: RuleEffect,
    operation: PolicyOperation,
    *,
    application: str | None = None,
    metadata_source: str | None = None,
) -> CaptureRule:
    return CaptureRule(
        rule_id=rule_id,
        effect=effect,
        operations=(operation,),
        application=application,
        metadata_source=metadata_source,
    )


def test_denied_pre_capture_context_never_invokes_screenshot() -> None:
    engine = _engine(_rule("deny-editor", RuleEffect.DENY, PolicyOperation.SCREENSHOT, application="Editor"))
    boundary = PolicyEnforcementBoundary(engine)
    calls: list[str] = []

    with pytest.raises(PermissionError, match="explicit-rule-deny"):
        boundary.capture(_context(), lambda: calls.append("screenshot"))

    assert calls == []


def test_privacy_mode_and_lock_never_invoke_screenshot() -> None:
    for state in ("privacy", "locked"):
        engine = _engine()
        boundary = PolicyEnforcementBoundary(engine)
        calls: list[str] = []
        if state == "privacy":
            engine.set_privacy_mode(True)
        else:
            engine.set_session_locked(True)

        with pytest.raises(PermissionError):
            boundary.capture(_context(), lambda: calls.append("screenshot"))

        assert calls == []


def test_uncertain_required_context_never_invokes_screenshot() -> None:
    rule = CaptureRule(
        rule_id="domain-required",
        effect=RuleEffect.DENY,
        operations=(PolicyOperation.SCREENSHOT,),
        domain="sensitive.example",
    )
    boundary = PolicyEnforcementBoundary(_engine(rule))
    calls: list[str] = []

    with pytest.raises(PermissionError, match="required-context-missing"):
        boundary.capture(_context(), lambda: calls.append("screenshot"))

    assert calls == []


def test_allowed_capture_redacts_before_persistence() -> None:
    engine = _engine()
    boundary = PolicyEnforcementBoundary(engine)
    context = _context()
    events: list[str] = []

    authorization, raw = boundary.capture(
        context,
        lambda: events.append("capture") or b"synthetic-pixels",
    )
    redacted = raw.replace(b"pixels", b"redacted")
    events.append("redaction")
    stored = boundary.persist(
        context,
        authorization,
        lambda: events.append("persistence") or redacted,
    )

    assert stored == b"synthetic-redacted"
    assert events == ["capture", "redaction", "persistence"]


def test_post_capture_policy_change_prevents_persistence() -> None:
    engine = _engine()
    boundary = PolicyEnforcementBoundary(engine)
    context = _context()
    calls: list[str] = []
    authorization, _raw = boundary.capture(context, lambda: b"synthetic")
    restrictive = LocalRecallConfig(
        profile=PrivacyProfile.LOCAL_FIRST,
        rules=RuleSettings(default_effect=RuleEffect.DENY),
    )
    engine.replace_policy(restrictive, revision="integration-policy-v2")

    with pytest.raises(PermissionError):
        boundary.persist(
            context,
            authorization,
            lambda: calls.append("persistence"),
        )

    assert calls == []


def test_denied_material_cannot_reach_index_summarizer_or_remote_provider() -> None:
    operations = (
        PolicyOperation.INDEXING,
        PolicyOperation.SUMMARIZATION,
        PolicyOperation.REMOTE_PROVIDER,
    )
    rules = tuple(
        _rule(f"deny-{operation.value}", RuleEffect.DENY, operation, application="Editor")
        for operation in operations
    )
    engine = _engine(*rules)
    boundary = PolicyEnforcementBoundary(engine)
    calls: list[PolicyOperation] = []

    for operation in operations:
        with pytest.raises(PermissionError):
            boundary.downstream(operation, _context(), lambda operation=operation: calls.append(operation))

    assert calls == []


def test_metadata_fallback_provenance_cannot_bypass_source_deny() -> None:
    rule = _rule(
        "deny-fallback",
        RuleEffect.DENY,
        PolicyOperation.SCREENSHOT,
        metadata_source="xorg-generic",
    )
    engine = _engine(rule)
    boundary = PolicyEnforcementBoundary(engine)
    calls: list[str] = []

    with pytest.raises(PermissionError):
        boundary.capture(
            _context(source_id="xorg-generic"),
            lambda: calls.append("screenshot"),
        )

    assert calls == []


@pytest.mark.parametrize("source_id", ["xorg-generic", "qtile", "activitywatch"])
def test_normalized_source_provenance_can_participate_in_policy(source_id: str) -> None:
    engine = _engine(
        _rule(
            f"deny-{source_id}",
            RuleEffect.DENY,
            PolicyOperation.SCREENSHOT,
            metadata_source=source_id,
        )
    )

    decision = engine.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        _context(source_id=source_id),
    )

    assert not decision.allowed
    assert decision.rule_id == f"deny-{source_id}"
