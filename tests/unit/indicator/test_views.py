from __future__ import annotations

from datetime import UTC, datetime

import local_recall.indicator as indicator
import local_recall.indicator_views as indicator_views


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
