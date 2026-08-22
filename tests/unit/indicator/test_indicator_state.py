from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from local_recall.cli_contract import (
    PROTOCOL_VERSION,
    CliLifecycleState,
    CliOutcome,
    CliRequest,
    CliResponse,
    CliStatusPayload,
)
from local_recall.indicator import IndicatorController, IndicatorState


@dataclass
class FakeClient:
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
            query_payload=response.query_payload,
            diagnostic_payload=response.diagnostic_payload,
            status_payload=response.status_payload,
        )


def status_response(
    state: CliLifecycleState,
    *,
    privacy_mode: bool = False,
    backend: str | None = "xorg",
    metadata_source: str | None = "qtile",
    captured_at: datetime | None = None,
) -> CliResponse:
    return CliResponse.success(
        request_id="placeholder",
        lifecycle_state=state,
        status_payload=CliStatusPayload(
            privacy_mode=privacy_mode,
            capture_backend=backend,
            metadata_source=metadata_source,
            last_capture_at=captured_at,
        ),
    )


def test_indicator_state_is_closed_and_content_free() -> None:
    assert tuple(state.value for state in IndicatorState) == (
        "off",
        "paused",
        "recording",
        "privacy",
        "locked",
        "overloaded",
        "faulted",
        "unavailable",
    )


def test_recording_requires_current_authoritative_status() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[
            status_response(
                CliLifecycleState.RECORDING,
                captured_at=now - timedelta(seconds=2),
            ),
            CliResponse.failure(
                request_id="placeholder",
                outcome=CliOutcome.UNAVAILABLE,
                reason_code="daemon-unavailable",
            ),
        ],
        requests=[],
    )
    controller = IndicatorController(client=client, timeout=timedelta(seconds=2))

    first = controller.refresh(now=now)
    second = controller.refresh(now=now + timedelta(seconds=3))

    assert first.state is IndicatorState.RECORDING
    assert first.capture_backend == "xorg"
    assert first.metadata_source == "qtile"
    assert second.state is IndicatorState.UNAVAILABLE
    assert second.capture_backend is None
    assert second.metadata_source is None
    assert second.last_capture_at is None


def test_privacy_is_authoritative_but_does_not_hide_lock() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[
            status_response(CliLifecycleState.PAUSED, privacy_mode=True),
            status_response(CliLifecycleState.LOCKED, privacy_mode=True),
        ],
        requests=[],
    )
    controller = IndicatorController(client=client, timeout=timedelta(seconds=2))

    assert controller.refresh(now=now).state is IndicatorState.PRIVACY
    assert controller.refresh(now=now + timedelta(seconds=1)).state is IndicatorState.LOCKED


def test_stop_and_privacy_controls_refresh_instead_of_mutating_optimistically() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[
            status_response(CliLifecycleState.RECORDING),
            status_response(CliLifecycleState.OFF, backend=None, metadata_source=None),
            status_response(CliLifecycleState.OFF, backend=None, metadata_source=None),
            status_response(CliLifecycleState.PAUSED, privacy_mode=True),
            status_response(CliLifecycleState.PAUSED, privacy_mode=True),
        ],
        requests=[],
    )
    controller = IndicatorController(client=client, timeout=timedelta(seconds=2))
    assert controller.refresh(now=now).state is IndicatorState.RECORDING

    stopped = controller.stop(now=now + timedelta(seconds=1))
    private = controller.privacy_on(now=now + timedelta(seconds=2))

    assert stopped.state is IndicatorState.OFF
    assert private.state is IndicatorState.PRIVACY
    assert [request.command.value for request in client.requests] == [
        "status",
        "stop",
        "status",
        "privacy-on",
        "status",
    ]


def test_snapshot_repr_never_contains_operational_identifiers() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[status_response(CliLifecycleState.RECORDING)],
        requests=[],
    )
    snapshot = IndicatorController(
        client=client, timeout=timedelta(seconds=2)
    ).refresh(now=now)

    assert "xorg" not in repr(snapshot)
    assert "qtile" not in repr(snapshot)
