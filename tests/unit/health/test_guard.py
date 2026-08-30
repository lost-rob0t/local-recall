from __future__ import annotations

import pytest

from local_recall.health.guard import (
    PrivacyDependencyFault,
    ensure_capture_allowed,
    ensure_persistence_allowed,
)
from local_recall.health.models import (
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
)


def _report(
    check_id: HealthCheckId,
    state: HealthState,
    reason_code: str = "synthetic",
) -> HealthReport:
    return HealthReport(
        results=(HealthCheckResult(check_id=check_id, state=state, reason_code=reason_code),)
    )


def test_healthy_report_allows_capture_and_persistence() -> None:
    report = _report(HealthCheckId.LIFECYCLE, HealthState.HEALTHY, "ok")
    ensure_capture_allowed(report)
    ensure_persistence_allowed(report)


def test_degraded_optional_feature_allows_capture_and_persistence() -> None:
    report = _report(HealthCheckId.OCR, HealthState.DEGRADED, "ocr-unavailable")
    ensure_capture_allowed(report)
    ensure_persistence_allowed(report)


@pytest.mark.parametrize(
    "check_id",
    [
        HealthCheckId.ENCRYPTION_KEYS,
        HealthCheckId.REDACTION,
        HealthCheckId.STORAGE_INTEGRITY,
    ],
)
def test_privacy_critical_failure_blocks_persistence(check_id: HealthCheckId) -> None:
    report = _report(check_id, HealthState.CAPTURE_BLOCKING, "failed")
    with pytest.raises(PrivacyDependencyFault):
        ensure_persistence_allowed(report)


@pytest.mark.parametrize(
    "check_id",
    [
        HealthCheckId.CAPTURE_BACKEND,
        HealthCheckId.ENCRYPTION_KEYS,
        HealthCheckId.REDACTION,
        HealthCheckId.DISK_QUOTA,
    ],
)
def test_capture_blocking_failures_block_capture(check_id: HealthCheckId) -> None:
    report = _report(check_id, HealthState.CAPTURE_BLOCKING, "failed")
    with pytest.raises(PrivacyDependencyFault):
        ensure_capture_allowed(report)


def test_degraded_state_never_blocks() -> None:
    for check_id in (
        HealthCheckId.ENCRYPTION_KEYS,
        HealthCheckId.REDACTION,
        HealthCheckId.CAPTURE_BACKEND,
    ):
        report = _report(check_id, HealthState.DEGRADED, "degraded")
        ensure_persistence_allowed(report)


def test_fault_is_content_free() -> None:
    report = _report(HealthCheckId.ENCRYPTION_KEYS, HealthState.CAPTURE_BLOCKING, "key-locked")
    with pytest.raises(PrivacyDependencyFault) as raised:
        ensure_persistence_allowed(report)
    assert str(raised.value) == "persistence-blocked-by-health"
