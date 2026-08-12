from __future__ import annotations

from datetime import UTC, datetime

from local_recall.config.models import CaptureRule, LocalRecallConfig, RuleEffect, RuleSettings
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextField, ContextMetadata, MetadataProvenance
from local_recall.domain.metadata import SourceConfidence
from local_recall.domain.policy import PolicyOperation, PolicyPhase, PolicyReasonCode
from local_recall.policy import PolicyEngine, PolicyEvaluationContext

NOW = datetime(2026, 8, 12, 16, 0, tzinfo=UTC)


def test_pre_capture_deny_blocks_screenshot_authorization() -> None:
    source = MetadataProvenance(
        source_id="xorg-generic",
        observed_at=NOW,
        confidence=SourceConfidence(1.0),
    )
    metadata = ContextMetadata(
        observed_at=NOW,
        fields=(
            ContextField(
                name="application",
                value="SecretApp",
                provenance=(source,),
            ),
        ),
    )
    configuration = LocalRecallConfig(
        rules=RuleSettings(
            default_effect=RuleEffect.ALLOW,
            rules=(
                CaptureRule(
                    rule_id="deny-secret-app",
                    effect=RuleEffect.DENY,
                    operations=(PolicyOperation.SCREENSHOT,),
                    application="SecretApp",
                ),
            ),
        )
    )
    policy = PolicyEngine(configuration, revision="policy-red-1")
    context = PolicyEvaluationContext(
        metadata=metadata,
        evaluated_at=NOW,
        capture_generation=CaptureGeneration(1),
    )

    decision = policy.evaluate(
        PolicyOperation.SCREENSHOT,
        PolicyPhase.PRE_CAPTURE,
        context,
    )

    assert not decision.allowed
    assert decision.reason_code is PolicyReasonCode.EXPLICIT_RULE_DENY
    assert decision.rule_id == "deny-secret-app"
