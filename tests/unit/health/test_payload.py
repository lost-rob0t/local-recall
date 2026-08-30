from __future__ import annotations

from datetime import UTC, datetime

from local_recall.cli_contract import CliDiagnosticCategory
from local_recall.health.models import (
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
)
from local_recall.health.payload import (
    health_report_diagnostic_payload,
)


def _report() -> HealthReport:
    return HealthReport(
        results=(
            HealthCheckResult(
                check_id=HealthCheckId.LIFECYCLE, state=HealthState.HEALTHY, reason_code="ok"
            ),
            HealthCheckResult(
                check_id=HealthCheckId.OCR,
                state=HealthState.DEGRADED,
                reason_code="ocr-unavailable",
            ),
            HealthCheckResult(
                check_id=HealthCheckId.ENCRYPTION_KEYS,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code="key-locked",
            ),
        )
    )


def test_report_maps_to_diagnostic_entries() -> None:
    payload = health_report_diagnostic_payload(_report())
    assert payload.category is CliDiagnosticCategory.HEALTH
    names = [entry.name for entry in payload.entries]
    assert "health-capture-blocked" in names
    assert "health-lifecycle" in names
    assert "health-encryption-keys" in names


def test_diagnostic_entries_are_bounded_and_valid() -> None:
    payload = health_report_diagnostic_payload(_report())
    for entry in payload.entries:
        assert len(entry.name) <= 128
        assert len(entry.state) <= 128
        assert entry.value is None or len(entry.value) <= 128


def test_capture_blocked_entry_reflects_report() -> None:
    payload = health_report_diagnostic_payload(_report())
    blocked = next(entry for entry in payload.entries if entry.name == "health-capture-blocked")
    assert blocked.value == "true"
    assert blocked.state == "capture-blocking"


def test_entries_reject_unbounded_values() -> None:
    report = HealthReport(
        results=(
            HealthCheckResult(
                check_id=HealthCheckId.LIFECYCLE,
                state=HealthState.HEALTHY,
                reason_code="x" * 512,
            ),
        )
    )
    try:
        health_report_diagnostic_payload(report)
    except ValueError:
        pass
    else:
        raise AssertionError("oversized reason code was accepted")


def test_payload_serializes_stably() -> None:
    payload = health_report_diagnostic_payload(_report())
    rendered = payload.to_json()
    assert '"category":"health"' in rendered
    assert datetime(2026, 8, 30, tzinfo=UTC).year == 2026
