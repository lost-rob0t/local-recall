from __future__ import annotations

import json
from typing import cast

from local_recall.health.bundle import build_diagnostic_bundle
from local_recall.health.models import HealthCheckId, HealthCheckResult, HealthState

_SEEDED_SECRET = "AKIASYNTHETICEXAMPLEKEY123"
_PLATFORM_MARKER = "linux"


def _report() -> object:
    from local_recall.health.models import HealthReport

    return HealthReport(
        results=(
            HealthCheckResult(
                check_id=HealthCheckId.LIFECYCLE, state=HealthState.HEALTHY, reason_code="ok"
            ),
            HealthCheckResult(
                check_id=HealthCheckId.ENCRYPTION_KEYS,
                state=HealthState.CAPTURE_BLOCKING,
                reason_code="key-locked",
            ),
        )
    )


def test_bundle_contains_versions_and_results_only() -> None:
    from datetime import UTC, datetime

    bundle = build_diagnostic_bundle(
        _report(),  # type: ignore[arg-type]
        now=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        record_count=42,
        storage_bytes=1024,
        revisions=("policy-v4", "config-v1"),
    )
    rendered = json.loads(bundle.to_json())
    document = cast("dict[str, object]", rendered)
    assert set(document) == {
        "generated_at",
        "application_version",
        "python_version",
        "platform_family",
        "results",
        "counts",
        "revisions",
    }
    assert document["platform_family"] == _PLATFORM_MARKER
    counts = cast("dict[str, object]", document["counts"])
    assert counts == {"records": 42, "storage_bytes": 1024}
    assert bundle.application_version


def test_bundle_is_content_free() -> None:
    from datetime import UTC, datetime

    bundle = build_diagnostic_bundle(
        _report(),
        now=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        record_count=1,
        storage_bytes=1,
        revisions=("policy-v4",),
    )
    rendered = bundle.to_json()
    assert _SEEDED_SECRET not in rendered
    assert "/" not in rendered
    assert "\\" not in rendered
    assert bundle.python_version.startswith("3.")
    assert bundle.storage_path is None


def test_bundle_json_is_stable_and_parseable() -> None:
    from datetime import UTC, datetime

    bundle = build_diagnostic_bundle(
        _report(),
        now=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        record_count=7,
        storage_bytes=8,
        revisions=(),
    )
    first = bundle.to_json()
    second = bundle.to_json()
    assert first == second
    document = cast("dict[str, object]", json.loads(first))
    assert isinstance(document["results"], list)
