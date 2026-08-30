"""Concurrent, sanitized health report assembly."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from local_recall.health.checks import HealthCheck
from local_recall.health.models import (
    HealthCheckCriticality,
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
    criticality_for,
)


class HealthService:
    def __init__(
        self,
        checks: Sequence[HealthCheck],
        *,
        per_check_timeout_seconds: float = 2.0,
    ) -> None:
        if per_check_timeout_seconds <= 0 or per_check_timeout_seconds > 60:
            raise ValueError("per-check timeout must be between 0 and 60 seconds")
        identifiers = [check.check_id for check in checks]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("health checks must be unique per check id")
        self._checks = tuple(checks)
        self._per_check_timeout_seconds = per_check_timeout_seconds

    async def report(self) -> HealthReport:
        results = await asyncio.gather(
            *(self._run_check(check) for check in self._checks),
            return_exceptions=False,
        )
        ordered = sorted(results, key=lambda result: result.check_id.value)
        return HealthReport(results=tuple(ordered))

    async def _run_check(self, check: HealthCheck) -> HealthCheckResult:
        try:
            return await asyncio.wait_for(check.check(), timeout=self._per_check_timeout_seconds)
        except TimeoutError:
            return HealthCheckResult(
                check_id=check.check_id,
                state=_failure_state(check.check_id),
                reason_code="health-check-timed-out",
            )
        except Exception:
            return HealthCheckResult(
                check_id=check.check_id,
                state=_failure_state(check.check_id),
                reason_code="health-check-failed",
            )


def _failure_state(check_id: HealthCheckId) -> HealthState:
    if criticality_for(check_id) is HealthCheckCriticality.OPTIONAL:
        return HealthState.DEGRADED
    return HealthState.CAPTURE_BLOCKING
