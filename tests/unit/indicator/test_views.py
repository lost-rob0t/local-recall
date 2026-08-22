from __future__ import annotations

import importlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast

import local_recall.indicator as indicator
from local_recall.cli_contract import (
    PROTOCOL_VERSION,
    CliLifecycleState,
    CliRequest,
    CliResponse,
    CliStatusPayload,
)


class Presentation(Protocol):
    status: str
    icon_name: str
    title: str
    tooltip: str


class QtileView(Protocol):
    def text(self, snapshot: indicator.IndicatorSnapshot) -> str: ...


class StatusNotifierView(Protocol):
    def present(self, snapshot: indicator.IndicatorSnapshot) -> Presentation: ...


class Surface(Protocol):
    def poll(self, *, now: datetime) -> indicator.IndicatorSnapshot: ...
    def stop(self, *, now: datetime) -> indicator.IndicatorSnapshot: ...
    def privacy_on(self, *, now: datetime) -> indicator.IndicatorSnapshot: ...
    def privacy_off(self, *, now: datetime) -> indicator.IndicatorSnapshot: ...


class ViewsModule(Protocol):
    QtileIndicatorView: type[QtileView]
    StatusNotifierItemView: type[StatusNotifierView]
    IndicatorSurface: type[Surface]


indicator_views = cast(
    ViewsModule,
    importlib.import_module("local_recall.indicator_views"),
)


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


def response(
    state: CliLifecycleState,
    *,
    privacy_mode: bool = False,
) -> CliResponse:
    return CliResponse.success(
        request_id="placeholder",
        lifecycle_state=state,
        status_payload=CliStatusPayload(
            privacy_mode=privacy_mode,
            capture_backend="xorg",
            metadata_source="qtile",
            last_capture_at=datetime(2026, 8, 22, 19, 59, 58, tzinfo=UTC),
        ),
    )


def snapshot(state: indicator.IndicatorState) -> indicator.IndicatorSnapshot:
    return indicator.IndicatorSnapshot(
        state=state,
        privacy_mode=state is indicator.IndicatorState.PRIVACY,
        observed_at=datetime(2026, 8, 22, 20, 0, tzinfo=UTC),
        capture_backend="xorg",
        metadata_source="qtile",
        last_capture_at=datetime(2026, 8, 22, 19, 59, 58, tzinfo=UTC),
    )


def test_qtile_text_is_closed_and_recording_is_visually_distinct() -> None:
    view = indicator_views.QtileIndicatorView()

    assert view.text(snapshot(indicator.IndicatorState.RECORDING)) == "LR:REC"
    assert view.text(snapshot(indicator.IndicatorState.OFF)) == "LR:OFF"
    assert view.text(snapshot(indicator.IndicatorState.PRIVACY)) == "LR:PRIV"
    assert view.text(snapshot(indicator.IndicatorState.UNAVAILABLE)) == "LR:?"


def test_status_notifier_recording_requests_attention() -> None:
    view = indicator_views.StatusNotifierItemView()

    recording = view.present(snapshot(indicator.IndicatorState.RECORDING))
    off = view.present(snapshot(indicator.IndicatorState.OFF))

    assert recording.status == "NeedsAttention"
    assert recording.icon_name == "local-recall-recording"
    assert off.status == "Passive"
    assert off.icon_name == "local-recall-off"


def test_tooltip_contains_only_bounded_operational_status() -> None:
    view = indicator_views.StatusNotifierItemView()
    presentation = view.present(snapshot(indicator.IndicatorState.RECORDING))

    assert presentation.title == "Local Recall"
    assert presentation.tooltip == (
        "recording; backend=xorg; metadata=qtile; last_capture=2026-08-22T19:59:58+00:00"
    )
    assert "screenshot" not in presentation.tooltip.lower()
    assert "ocr" not in presentation.tooltip.lower()
    assert "command" not in presentation.tooltip.lower()
    assert "provider" not in presentation.tooltip.lower()
    assert "path" not in presentation.tooltip.lower()
    assert "xorg" not in repr(presentation)
    assert "qtile" not in repr(presentation)


def test_surface_exposes_one_action_controls_and_always_refreshes() -> None:
    now = datetime(2026, 8, 22, 20, 0, tzinfo=UTC)
    client = FakeClient(
        responses=[
            response(CliLifecycleState.RECORDING),
            response(CliLifecycleState.OFF),
            response(CliLifecycleState.OFF),
            response(CliLifecycleState.PAUSED, privacy_mode=True),
            response(CliLifecycleState.PAUSED, privacy_mode=True),
            response(CliLifecycleState.PAUSED),
            response(CliLifecycleState.PAUSED),
        ],
        requests=[],
    )
    controller = indicator.IndicatorController(client=client, timeout=timedelta(seconds=2))
    surface = indicator_views.IndicatorSurface(controller)

    assert surface.poll(now=now).state is indicator.IndicatorState.RECORDING
    assert surface.stop(now=now).state is indicator.IndicatorState.OFF
    assert surface.privacy_on(now=now).state is indicator.IndicatorState.PRIVACY
    assert surface.privacy_off(now=now).state is indicator.IndicatorState.PAUSED
    assert [request.command.value for request in client.requests] == [
        "status",
        "stop",
        "status",
        "privacy-on",
        "status",
        "privacy-off",
        "status",
    ]
