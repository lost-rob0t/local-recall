from __future__ import annotations

from datetime import UTC, datetime

import pytest

from local_recall.cli_contract import (
    CliLifecycleState,
    CliResponse,
    CliStatusPayload,
)


@pytest.mark.parametrize(
    "value",
    ["terminal\nsecret", "/home/user/private", "user@example.com", "a" * 129],
)
def test_status_payload_rejects_content_like_operational_identifiers(value: str) -> None:
    with pytest.raises(ValueError):
        CliStatusPayload(
            privacy_mode=False,
            capture_backend=value,
            metadata_source="qtile",
            last_capture_at=None,
        )


def test_status_payload_requires_aware_last_capture_timestamp() -> None:
    with pytest.raises(ValueError):
        CliStatusPayload(
            privacy_mode=False,
            capture_backend="xorg",
            metadata_source="qtile",
            last_capture_at=datetime(2026, 8, 22, 20, 0),
        )


def test_status_payload_is_content_minimizing() -> None:
    payload = CliStatusPayload(
        privacy_mode=True,
        capture_backend="xorg",
        metadata_source="qtile",
        last_capture_at=datetime(2026, 8, 22, 20, 0, tzinfo=UTC),
    )

    assert payload.privacy_mode is True
    assert payload.capture_backend == "xorg"
    assert payload.metadata_source == "qtile"
    assert "xorg" not in repr(payload)
    assert "qtile" not in repr(payload)


def test_status_response_carries_lifecycle_and_status_payload_together() -> None:
    payload = CliStatusPayload(
        privacy_mode=False,
        capture_backend="xorg",
        metadata_source="qtile",
        last_capture_at=datetime(2026, 8, 22, 20, 0, tzinfo=UTC),
    )

    response = CliResponse.success(
        request_id="request-1",
        lifecycle_state=CliLifecycleState.RECORDING,
        status_payload=payload,
    )

    assert response.lifecycle_state is CliLifecycleState.RECORDING
    assert response.status_payload is payload
    assert "xorg" not in repr(response)
    assert "qtile" not in repr(response)
