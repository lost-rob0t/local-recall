from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from local_recall.domain.policy import PolicyAuthorization, PolicyOperation, PolicyPhase

from .engine import PolicyEngine, PolicyEvaluationContext
from .guard import PolicyGuard

ResultT = TypeVar("ResultT")


class PolicyEnforcementBoundary:
    """Typed side-effect boundary for capture, persistence, and downstream work."""

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine
        self._guard = PolicyGuard(engine)

    def capture(
        self,
        context: PolicyEvaluationContext,
        action: Callable[[], ResultT],
    ) -> tuple[PolicyAuthorization, ResultT]:
        authorization = self._engine.authorize(
            PolicyOperation.SCREENSHOT,
            PolicyPhase.PRE_CAPTURE,
            context,
        )
        result = self._guard.invoke(
            authorization,
            capture_generation=context.capture_generation,
            action=action,
        )
        return authorization, result

    def persist(
        self,
        context: PolicyEvaluationContext,
        authorization: PolicyAuthorization,
        action: Callable[[], ResultT],
    ) -> ResultT:
        decision = self._engine.evaluate(
            PolicyOperation.SCREENSHOT,
            PolicyPhase.POST_CAPTURE,
            context,
        )
        self._guard.require_allowed(decision)
        return self._guard.invoke(
            authorization,
            capture_generation=context.capture_generation,
            action=action,
        )

    def downstream(
        self,
        operation: PolicyOperation,
        context: PolicyEvaluationContext,
        action: Callable[[], ResultT],
    ) -> ResultT:
        if operation in {PolicyOperation.SCREENSHOT, PolicyOperation.METADATA}:
            raise ValueError("capture operations must use their phase-specific boundary")
        authorization = self._engine.authorize(operation, PolicyPhase.DOWNSTREAM, context)
        return self._guard.invoke(
            authorization,
            capture_generation=context.capture_generation,
            action=action,
        )
