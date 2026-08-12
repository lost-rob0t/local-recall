from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.domain.policy import PolicyAuthorization, PolicyDecision

from .engine import PolicyEngine

T = TypeVar("T")


class PolicyGuard:
    """Executes a side effect only while its policy authorization is still current."""

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine

    @staticmethod
    def require_allowed(decision: PolicyDecision) -> None:
        if decision.allowed and decision.certain:
            return
        raise PermissionError(f"policy denied: {decision.reason_code.value}")

    def invoke(
        self,
        authorization: PolicyAuthorization,
        *,
        capture_generation: CaptureGeneration,
        action: Callable[[], T],
    ) -> T:
        if not self._engine.is_authorization_current(
            authorization,
            capture_generation=capture_generation,
        ):
            raise PermissionError("policy denied: stale-authorization")
        return action()
