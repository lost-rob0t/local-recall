from datetime import UTC, datetime
from uuid import uuid4

import pytest

from local_recall.domain.capture import (
    ApprovedCaptureRequest,
    CaptureDecision,
    CaptureIntent,
)
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.metadata import ContextMetadata


def intent() -> CaptureIntent:
    return CaptureIntent(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        requested_at=datetime.now(UTC),
        deadline_monotonic_ns=1,
        configuration_revision="config-v1",
    )


def metadata() -> ContextMetadata:
    return ContextMetadata(observed_at=datetime.now(UTC), fields=())


def test_denied_decision_cannot_create_approved_request() -> None:
    with pytest.raises(PermissionError, match="capture denied"):
        ApprovedCaptureRequest.from_decision(
            intent=intent(),
            metadata=metadata(),
            decision=CaptureDecision.deny(reason_code="sensitive-context"),
        )


def test_allowed_decision_carries_policy_revision() -> None:
    request = ApprovedCaptureRequest.from_decision(
        intent=intent(),
        metadata=metadata(),
        decision=CaptureDecision.allow(
            policy_revision="policy-v1",
            allowed_metadata_fields=frozenset({"application"}),
        ),
    )

    assert request.authorization.policy_revision == "policy-v1"
