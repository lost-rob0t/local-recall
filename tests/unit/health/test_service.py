from __future__ import annotations

import asyncio
import json
from typing import cast

from local_recall.health.checks import HealthCheck
from local_recall.health.models import (
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
)
from local_recall.health.service import HealthService

from .test_checks import FakePorts, build


class _FailingRedactionCheck:
    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.REDACTION

    async def check(self) -> HealthCheckResult:
        raise RuntimeError("synthetic-sensitive-redaction-marker")


class _BlockingRedactionCheck:
    @property
    def check_id(self) -> HealthCheckId:
        return HealthCheckId.REDACTION

    async def check(self) -> HealthCheckResult:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


def _with_replacement(check_id: HealthCheckId, replacement: object) -> tuple[HealthCheck, ...]:
    return tuple(
        replacement if check.check_id is check_id else check for check in build(FakePorts())
    )  # type: ignore[return-value]


def test_service_returns_full_report_with_all_checks() -> None:
    service = HealthService(checks=build(FakePorts()), per_check_timeout_seconds=1.0)
    report = asyncio.run(service.report())
    assert len(report.results) == len(HealthCheckId)
    assert report.capture_blocked is False
    assert report.overall is HealthState.HEALTHY


def test_service_maps_check_exception_to_sanitized_state() -> None:
    service = HealthService(
        checks=_with_replacement(HealthCheckId.REDACTION, _FailingRedactionCheck()),
        per_check_timeout_seconds=1.0,
    )
    report = asyncio.run(service.report())
    redaction = report.check(HealthCheckId.REDACTION)
    assert redaction is not None
    assert redaction.state is HealthState.CAPTURE_BLOCKING
    assert redaction.reason_code == "health-check-failed"
    assert "synthetic-sensitive-redaction-marker" not in repr(report)


def test_service_timeout_is_sanitized() -> None:
    service = HealthService(
        checks=_with_replacement(HealthCheckId.REDACTION, _BlockingRedactionCheck()),
        per_check_timeout_seconds=0.05,
    )
    report = asyncio.run(service.report())
    redaction = report.check(HealthCheckId.REDACTION)
    assert redaction is not None
    assert redaction.state is HealthState.CAPTURE_BLOCKING
    assert redaction.reason_code == "health-check-timed-out"


def test_report_serializes_to_closed_json_keys() -> None:
    service = HealthService(checks=build(FakePorts()), per_check_timeout_seconds=1.0)
    report = asyncio.run(service.report())
    rendered: object = json.loads(report.to_json())
    assert isinstance(rendered, dict)
    document = cast("dict[str, object]", rendered)
    assert set(document) == {"capture_blocked", "overall", "results"}
    entries = document["results"]
    assert isinstance(entries, list)
    for entry in cast("list[object]", entries):
        assert isinstance(entry, dict)
        assert set(cast("dict[str, object]", entry)) == {"check_id", "state", "reason_code"}


def test_report_to_dict_reports_blocked_state() -> None:
    report = HealthReport(
        results=(
            HealthCheckResult(
                check_id=HealthCheckId.ENCRYPTION_KEYS,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code="key-locked",
            ),
        )
    )
    document = report.to_dict()
    assert document["capture_blocked"] is True
    assert document["overall"] == "capture-blocking"
