from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from local_recall.cli_contract import (
    PROTOCOL_VERSION,
    CliLifecycleState,
    CliOutcome,
    CliRequest,
    CliResponse,
    CliStatusPayload,
)
from local_recall.indicator import IndicatorController, IndicatorState
from local_recall.indicator_views import (
    IndicatorSurface,
    QtileIndicatorAdapter,
    StatusNotifierItemAdapter,
)

pytestmark = pytest.mark.integration


@dataclass
class RestartingDaemonClient:
    responses: list[CliResponse]
    requests: list[CliRequest]

    def request(self, request: CliRequest) -> CliResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        return CliResponse(
            protocol_version=PROTOCOL_VERSION,
            request_id=request.request_id,
            outcome=response.outcome,
            reason_code=response.reason_code,
            lifecycle_state=response.lifecycle_state,
            status_payload=response.status_payload,
        )


def status(state: CliLifecycleState, *, privacy_mode: bool = False) -> CliResponse:
    return CliResponse.success(
        request_id="placeholder",
        lifecycle_state=state,
        status_payload=CliStatusPayload(
            privacy_mode=privacy_mode,
            capture_backend="xorg",
            metadata_source="qtile",
            last_capture_at=datetime(2026, 8, 22, 20, 0, tzinfo=UTC),
        ),
    )


def unavailable() -> CliResponse:
    return CliResponse.failure(
        request_id="placeholder",
        outcome=CliOutcome.UNAVAILABLE,
        reason_code="daemon-unavailable",
    )


def test_indicator_discards_recording_across_daemon_restart_then_recovers() -> None:
    now = datetime(2026, 8, 22, 20, 1, tzinfo=UTC)
    client = RestartingDaemonClient(
        responses=[
            status(CliLifecycleState.RECORDING),
            unavailable(),
            status(CliLifecycleState.PAUSED),
        ],
        requests=[],
    )
    surface = IndicatorSurface(IndicatorController(client=client, timeout=timedelta(seconds=2)))
    qtile = QtileIndicatorAdapter(surface)

    assert qtile.poll_text(now=now) == "LR:REC"
    assert qtile.poll_text(now=now + timedelta(seconds=1)) == "LR:?"
    assert qtile.poll_text(now=now + timedelta(seconds=2)) == "LR:PAUSE"
    assert [request.command.value for request in client.requests] == ["status", "status", "status"]


def test_tray_stop_and_privacy_actions_render_only_refreshed_daemon_state() -> None:
    now = datetime(2026, 8, 22, 20, 1, tzinfo=UTC)
    client = RestartingDaemonClient(
        responses=[
            status(CliLifecycleState.OFF),
            status(CliLifecycleState.OFF),
            status(CliLifecycleState.PAUSED, privacy_mode=True),
            status(CliLifecycleState.PAUSED, privacy_mode=True),
        ],
        requests=[],
    )
    tray = StatusNotifierItemAdapter(
        IndicatorSurface(IndicatorController(client=client, timeout=timedelta(seconds=2)))
    )

    assert tray.stop(now=now).icon_name == "local-recall-off"
    private = tray.privacy_on(now=now + timedelta(seconds=1))
    assert private.icon_name == "local-recall-privacy"
    assert "privacy" in private.tooltip
    assert [request.command.value for request in client.requests] == [
        "stop",
        "status",
        "privacy-on",
        "status",
    ]


def test_failed_refresh_never_preserves_recording_metadata() -> None:
    now = datetime(2026, 8, 22, 20, 1, tzinfo=UTC)
    client = RestartingDaemonClient(
        responses=[status(CliLifecycleState.RECORDING), unavailable()],
        requests=[],
    )
    controller = IndicatorController(client=client, timeout=timedelta(seconds=2))

    assert controller.refresh(now=now).state is IndicatorState.RECORDING
    failed = controller.refresh(now=now + timedelta(seconds=1))

    assert failed.state is IndicatorState.UNAVAILABLE
    assert failed.capture_backend is None
    assert failed.metadata_source is None
    assert failed.last_capture_at is None
