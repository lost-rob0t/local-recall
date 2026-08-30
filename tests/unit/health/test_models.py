from __future__ import annotations

import pytest

from local_recall.health.models import (
    HealthCheckId,
    HealthCheckResult,
    HealthReport,
    HealthState,
)


def _result(
    check_id: HealthCheckId,
    state: HealthState = HealthState.HEALTHY,
    reason_code: str = "ok",
) -> HealthCheckResult:
    return HealthCheckResult(check_id=check_id, state=state, reason_code=reason_code)


def test_check_ids_cover_required_surfaces() -> None:
    required = {
        "lifecycle",
        "capture-backend",
        "metadata-sources",
        "ocr",
        "encryption-keys",
        "redaction",
        "storage-integrity",
        "indexes",
        "model-providers",
        "disk-quota",
        "daemon-ipc",
    }
    assert {item.value for item in HealthCheckId} == required


def test_empty_report_is_healthy_and_not_capture_blocking() -> None:
    report = HealthReport(results=())
    assert report.capture_blocked is False
    assert report.overall is HealthState.HEALTHY


def test_capture_blocking_is_derived_from_any_blocking_check() -> None:
    report = HealthReport(
        results=(
            _result(HealthCheckId.LIFECYCLE),
            _result(HealthCheckId.ENCRYPTION_KEYS, HealthState.CAPTURE_BLOCKING, "key-locked"),
            _result(HealthCheckId.OCR, HealthState.DEGRADED, "ocr-unavailable"),
        )
    )
    assert report.capture_blocked is True
    assert report.overall is HealthState.CAPTURE_BLOCKING


def test_degraded_optional_features_do_not_block_capture() -> None:
    report = HealthReport(
        results=(
            _result(HealthCheckId.LIFECYCLE),
            _result(HealthCheckId.OCR, HealthState.DEGRADED, "ocr-unavailable"),
            _result(HealthCheckId.MODEL_PROVIDERS, HealthState.DEGRADED, "provider-offline"),
            _result(HealthCheckId.DAEMON_IPC, HealthState.DEGRADED, "ipc-unresponsive"),
        )
    )
    assert report.capture_blocked is False
    assert report.overall is HealthState.DEGRADED


def test_check_lookup_returns_matching_result() -> None:
    report = HealthReport(results=(_result(HealthCheckId.REDACTION),))
    assert report.check(HealthCheckId.REDACTION) is not None
    assert report.check(HealthCheckId.DISK_QUOTA) is None


def test_duplicate_check_results_are_rejected() -> None:
    with pytest.raises(ValueError):
        HealthReport(results=(_result(HealthCheckId.REDACTION), _result(HealthCheckId.REDACTION)))


def test_reason_codes_are_required() -> None:
    with pytest.raises(ValueError):
        HealthCheckResult(
            check_id=HealthCheckId.REDACTION, state=HealthState.HEALTHY, reason_code=""
        )


def test_result_repr_is_content_free() -> None:
    result = _result(HealthCheckId.ENCRYPTION_KEYS, HealthState.CAPTURE_BLOCKING, "key-locked")
    rendered = repr(result)
    assert "encryption-keys" not in rendered
    assert "key-locked" not in rendered


def test_report_repr_is_content_free() -> None:
    report = HealthReport(
        results=(_result(HealthCheckId.ENCRYPTION_KEYS, HealthState.CAPTURE_BLOCKING),)
    )
    assert "encryption" not in repr(report)
