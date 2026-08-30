"""Mapping from health reports to the closed IPC diagnostic payload."""

from __future__ import annotations

from local_recall.cli_contract import (
    CliDiagnosticCategory,
    CliDiagnosticEntry,
    CliDiagnosticPayload,
)
from local_recall.health.models import HealthReport

_CAPTURE_BLOCKED_NAME = "health-capture-blocked"
_PREFIX = "health-"


def health_report_diagnostic_entries(report: HealthReport) -> tuple[CliDiagnosticEntry, ...]:
    entries = [
        CliDiagnosticEntry(
            name=_CAPTURE_BLOCKED_NAME,
            state=report.overall.value if report.capture_blocked else "healthy",
            value="true" if report.capture_blocked else "false",
        )
    ]
    for result in report.results:
        entries.append(
            CliDiagnosticEntry(
                name=f"{_PREFIX}{result.check_id.value}",
                state=result.state.value,
                value=result.reason_code,
            )
        )
    return tuple(entries)


def health_report_diagnostic_payload(report: HealthReport) -> CliDiagnosticPayload:
    return CliDiagnosticPayload(
        category=CliDiagnosticCategory.HEALTH,
        entries=health_report_diagnostic_entries(report),
    )
