from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from local_recall.domain.capture import CaptureDecision, CapturePolicyInput
from local_recall.domain.policy import PolicyOperation, PolicyPhase

from .engine import PolicyEngine, PolicyEvaluationContext


class CapturePolicyAdapter:
    def __init__(
        self,
        engine: PolicyEngine,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._engine = engine
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def revision(self) -> str:
        return self._engine.revision

    async def evaluate(self, request: CapturePolicyInput) -> CaptureDecision:
        context = PolicyEvaluationContext(
            metadata=request.metadata,
            evaluated_at=self._clock(),
            capture_generation=request.intent.generation,
        )
        decision = self._engine.evaluate(
            PolicyOperation.SCREENSHOT,
            PolicyPhase.PRE_CAPTURE,
            context,
        )
        if not decision.allowed or not decision.certain:
            return CaptureDecision.deny(reason_code=decision.reason_code.value)
        return CaptureDecision.allow(
            policy_revision=decision.policy_revision,
            allowed_metadata_fields=frozenset(field.name for field in request.metadata.fields),
            reason_code=decision.reason_code.value,
        )
