from __future__ import annotations

from datetime import UTC, datetime

from local_recall import policy as capture_policy
from local_recall.config import models as config_models
from local_recall.domain import lifecycle as lifecycle_domain
from local_recall.domain import metadata as metadata_domain
from local_recall.domain import policy as policy_domain

NOW = datetime(2026, 8, 12, 16, 0, tzinfo=UTC)


def test_pre_capture_deny_blocks_screenshot_authorization() -> None:
    source = metadata_domain.MetadataProvenance(
        source_id="xorg-generic",
        observed_at=NOW,
        confidence=metadata_domain.SourceConfidence(1.0),
    )
    metadata = metadata_domain.ContextMetadata(
        observed_at=NOW,
        fields=(
            metadata_domain.ContextField(
                name="application",
                value="SecretApp",
                provenance=(source,),
            ),
        ),
    )
    configuration = config_models.LocalRecallConfig(
        profile=config_models.PrivacyProfile.LOCAL_FIRST,
        rules=config_models.RuleSettings(
            default_effect=config_models.RuleEffect.ALLOW,
            rules=(
                config_models.CaptureRule(
                    rule_id="deny-secret-app",
                    effect=config_models.RuleEffect.DENY,
                    operations=(policy_domain.PolicyOperation.SCREENSHOT,),
                    application="SecretApp",
                ),
            ),
        ),
    )
    policy = capture_policy.PolicyEngine(configuration, revision="policy-red-1")
    context = capture_policy.PolicyEvaluationContext(
        metadata=metadata,
        evaluated_at=NOW,
        capture_generation=lifecycle_domain.CaptureGeneration(1),
    )

    decision = policy.evaluate(
        policy_domain.PolicyOperation.SCREENSHOT,
        policy_domain.PolicyPhase.PRE_CAPTURE,
        context,
    )

    assert not decision.allowed
    assert decision.reason_code is policy_domain.PolicyReasonCode.EXPLICIT_RULE_DENY
    assert decision.rule_id == "deny-secret-app"
