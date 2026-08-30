"""Privacy gates that translate health reports into hard persistence rules."""

from __future__ import annotations

from local_recall.health.models import HealthCheckId, HealthReport, HealthState

_PERSISTENCE_BLOCKING_CHECKS = (
    HealthCheckId.ENCRYPTION_KEYS,
    HealthCheckId.REDACTION,
    HealthCheckId.STORAGE_INTEGRITY,
)


class PrivacyDependencyFault(RuntimeError):
    """Content-free refusal to run capture or persistence work."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def ensure_capture_allowed(report: HealthReport) -> None:
    """Refuse capture while any check reports a capture-blocking failure."""
    if report.capture_blocked:
        raise PrivacyDependencyFault("capture-blocked-by-health")


def ensure_persistence_allowed(report: HealthReport) -> None:
    """Refuse persistence when a critical privacy dependency is failing."""
    for check_id in _PERSISTENCE_BLOCKING_CHECKS:
        result = report.check(check_id)
        if result is not None and result.state is HealthState.CAPTURE_BLOCKING:
            raise PrivacyDependencyFault("persistence-blocked-by-health")
