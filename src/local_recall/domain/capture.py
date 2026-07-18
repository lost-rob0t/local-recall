from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from ._validation import require_aware, require_nonempty
from .lifecycle import CaptureGeneration
from .metadata import ContextMetadata


@dataclass(frozen=True, slots=True)
class CaptureIntent:
    job_id: UUID
    generation: CaptureGeneration
    requested_at: datetime
    deadline_monotonic_ns: int
    configuration_revision: str

    def __post_init__(self) -> None:
        require_aware(self.requested_at, "requested_at")
        if self.deadline_monotonic_ns <= 0:
            raise ValueError("deadline must be positive")
        require_nonempty(self.configuration_revision, "configuration_revision")


@dataclass(frozen=True, slots=True)
class MetadataRequest:
    job_id: UUID
    generation: CaptureGeneration
    deadline_monotonic_ns: int
    requested_fields: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.deadline_monotonic_ns <= 0:
            raise ValueError("deadline must be positive")


class CaptureDecisionKind(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class CaptureAuthorization:
    decision_id: UUID
    policy_revision: str
    allowed_metadata_fields: frozenset[str]

    def __post_init__(self) -> None:
        require_nonempty(self.policy_revision, "policy_revision")


@dataclass(frozen=True, slots=True)
class CaptureDecision:
    kind: CaptureDecisionKind
    reason_code: str
    authorization: CaptureAuthorization | None
    decision_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        require_nonempty(self.reason_code, "reason_code")
        if self.kind is CaptureDecisionKind.ALLOW and self.authorization is None:
            raise ValueError("allow decisions require capture authorization")
        if self.kind is CaptureDecisionKind.DENY and self.authorization is not None:
            raise ValueError("deny decisions cannot include capture authorization")

    @classmethod
    def allow(
        cls,
        *,
        policy_revision: str,
        allowed_metadata_fields: frozenset[str],
        reason_code: str = "allowed",
    ) -> CaptureDecision:
        decision_id = uuid4()
        return cls(
            kind=CaptureDecisionKind.ALLOW,
            reason_code=reason_code,
            authorization=CaptureAuthorization(
                decision_id=decision_id,
                policy_revision=policy_revision,
                allowed_metadata_fields=allowed_metadata_fields,
            ),
            decision_id=decision_id,
        )

    @classmethod
    def deny(cls, *, reason_code: str) -> CaptureDecision:
        return cls(
            kind=CaptureDecisionKind.DENY,
            reason_code=reason_code,
            authorization=None,
        )

    def require_authorization(self) -> CaptureAuthorization:
        if self.authorization is None:
            raise PermissionError(f"capture denied: {self.reason_code}")
        return self.authorization


@dataclass(frozen=True, slots=True)
class CapturePolicyInput:
    intent: CaptureIntent
    metadata: ContextMetadata


@dataclass(frozen=True, slots=True)
class ApprovedCaptureRequest:
    intent: CaptureIntent
    metadata: ContextMetadata
    authorization: CaptureAuthorization

    @classmethod
    def from_decision(
        cls,
        *,
        intent: CaptureIntent,
        metadata: ContextMetadata,
        decision: CaptureDecision,
    ) -> ApprovedCaptureRequest:
        return cls(
            intent=intent,
            metadata=metadata,
            authorization=decision.require_authorization(),
        )
