from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import local_recall.cli_contract as cli_contract
import local_recall.indicator as indicator


@dataclass
class FakeClient:
    responses: list[cli_contract.CliResponse]
    requests: list[cli_contract.CliRequest]

    def request(self, request: cli_contract.CliRequest) -> cli_contract.CliResponse:
        self.requests.append(request)
        response = self.responses.pop(0)
        return cli_contract.CliResponse(
            protocol_version=response.protocol_version,
            request_id=request.request_id,
            outcome=response.outcome,
            reason_code=response.reason_code,
            lifecycle_state=response.lifecycle_state,
            status_payload=response.status_payload,
        )


def status_response(
    state: cli_contract.CliLifecycleState,
    *,
    privacy_mode: bool = False,
    backend: str | None = "xorg",
    metadata_source: str | None = "qtile",
    captured_at: datetime | None = None,
) -> cli_contract.CliResponse:
    return cli_contract.CliResponse.success(
        request_id="placeholder",
        lifecycle_state=state,
        status_payload=cli_contract.CliStatusPayload(
            privacy_mode=privacy_mode,
            capture_backend=backend,
            metadata_source=metadata_source,
            last_capture_at=captured_at,
        ),
    )


def test_recording_requires_current_authoritative_status() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[
            status_response(
                cli_contract.CliLifecycleState.RECORDING,
                captured_at=now - timedelta(seconds=2),
            ),
            cli_contract.CliResponse.failure(
                request_id="placeholder",
                outcome=cli_contract.CliOutcome.UNAVAILABLE,
                reason_code="daemon-unavailable",
            ),
        ],
        requests=[],
    )
    controller = indicator.IndicatorController(client=client, timeout=timedelta(seconds=2))

    first = controller.refresh(now=now)
    second = controller.refresh(now=now + timedelta(seconds=3))

    assert first.state is indicator.IndicatorState.RECORDING
    assert first.capture_backend == "xorg"
    assert second.state is indicator.IndicatorState.UNAVAILABLE
    assert second.capture_backend is None
    assert second.metadata_source is None
    assert second.last_capture_at is None


def test_privacy_mode_is_authoritative_and_not_inferred_from_pause() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[status_response(cli_contract.CliLifecycleState.PAUSED, privacy_mode=True)],
        requests=[],
    )
    controller = indicator.IndicatorController(client=client, timeout=timedelta(seconds=2))

    snapshot = controller.refresh(now=now)

    assert snapshot.state is indicator.IndicatorState.PRIVACY
    assert snapshot.privacy_mode is True


def test_stop_does_not_optimistically_change_state() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[
            status_response(cli_contract.CliLifecycleState.RECORDING),
            status_response(
                cli_contract.CliLifecycleState.OFF,
                backend=None,
                metadata_source=None,
            ),
            status_response(
                cli_contract.CliLifecycleState.OFF,
                backend=None,
                metadata_source=None,
            ),
        ],
        requests=[],
    )
    controller = indicator.IndicatorController(client=client, timeout=timedelta(seconds=2))
    assert controller.refresh(now=now).state is indicator.IndicatorState.RECORDING

    result = controller.stop(now=now + timedelta(seconds=1))

    assert result.state is indicator.IndicatorState.OFF
    assert [request.command.value for request in client.requests] == ["status", "stop", "status"]


def test_status_payload_rejects_content_like_operational_identifiers() -> None:
    for value in ("terminal\nsecret", "/home/user/private", "user@example.com", "a" * 129):
        try:
            cli_contract.CliStatusPayload(
                privacy_mode=False,
                capture_backend=value,
                metadata_source="qtile",
                last_capture_at=None,
            )
        except ValueError:
            continue
        raise AssertionError(f"unsafe status value accepted: {value!r}")
