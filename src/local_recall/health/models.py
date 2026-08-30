"""Closed health-check model types with content-free rendering."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum


class HealthCheckId(StrEnum):
    LIFECYCLE = "lifecycle"
    CAPTURE_BACKEND = "capture-backend"
    METADATA_SOURCES = "metadata-sources"
    OCR = "ocr"
    ENCRYPTION_KEYS = "encryption-keys"
    REDACTION = "redaction"
    STORAGE_INTEGRITY = "storage-integrity"
    INDEXES = "indexes"
    MODEL_PROVIDERS = "model-providers"
    DISK_QUOTA = "disk-quota"
    DAEMON_IPC = "daemon-ipc"


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CAPTURE_BLOCKING = "capture-blocking"


class HealthCheckCriticality(StrEnum):
    OPTIONAL = "optional"
    PRIVACY_CRITICAL = "privacy-critical"


_OPTIONAL_CHECKS = frozenset(
    {
        HealthCheckId.METADATA_SOURCES,
        HealthCheckId.OCR,
        HealthCheckId.INDEXES,
        HealthCheckId.MODEL_PROVIDERS,
        HealthCheckId.DAEMON_IPC,
    }
)


def criticality_for(check_id: HealthCheckId) -> HealthCheckCriticality:
    if check_id in _OPTIONAL_CHECKS:
        return HealthCheckCriticality.OPTIONAL
    return HealthCheckCriticality.PRIVACY_CRITICAL


@dataclass(frozen=True, slots=True, repr=False)
class HealthCheckResult:
    check_id: HealthCheckId
    state: HealthState
    reason_code: str

    def __post_init__(self) -> None:
        if not self.reason_code:
            raise ValueError("health check reason code must not be empty")

    def __repr__(self) -> str:
        return f"HealthCheckResult(check_id=<opaque>, state={self.state.value!r}, reason=<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class HealthReport:
    results: tuple[HealthCheckResult, ...]

    def __post_init__(self) -> None:
        identifiers = [result.check_id for result in self.results]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("health check results must be unique per check id")

    @property
    def capture_blocked(self) -> bool:
        return any(result.state is HealthState.CAPTURE_BLOCKING for result in self.results)

    @property
    def overall(self) -> HealthState:
        if self.capture_blocked:
            return HealthState.CAPTURE_BLOCKING
        if any(result.state is HealthState.DEGRADED for result in self.results):
            return HealthState.DEGRADED
        return HealthState.HEALTHY

    def check(self, check_id: HealthCheckId) -> HealthCheckResult | None:
        for result in self.results:
            if result.check_id is check_id:
                return result
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "capture_blocked": self.capture_blocked,
            "overall": self.overall.value,
            "results": [
                {
                    "check_id": result.check_id.value,
                    "state": result.state.value,
                    "reason_code": result.reason_code,
                }
                for result in self.results
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def __repr__(self) -> str:
        return (
            f"HealthReport(results={len(self.results)}, overall={self.overall.value!r}, "
            "content=redacted)"
        )
