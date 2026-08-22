"""Dependency-light desktop presentation adapters for Local Recall indicators."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from local_recall.indicator import IndicatorController, IndicatorSnapshot, IndicatorState

_QTILE_TEXT = {
    IndicatorState.OFF: "LR:OFF",
    IndicatorState.PAUSED: "LR:PAUSE",
    IndicatorState.RECORDING: "LR:REC",
    IndicatorState.PRIVACY: "LR:PRIV",
    IndicatorState.LOCKED: "LR:LOCK",
    IndicatorState.OVERLOADED: "LR:LOAD",
    IndicatorState.FAULTED: "LR:FAULT",
    IndicatorState.UNAVAILABLE: "LR:?",
}

_ICON_NAME = {state: f"local-recall-{state.value}" for state in IndicatorState}


@dataclass(frozen=True, slots=True, repr=False)
class StatusNotifierPresentation:
    """StatusNotifierItem-compatible content-free presentation values."""

    status: str
    icon_name: str
    title: str
    tooltip: str

    def __repr__(self) -> str:
        return (
            "StatusNotifierPresentation("
            f"status={self.status!r}, icon_name={self.icon_name!r}, "
            "title=<fixed>, tooltip=<content-free-status>)"
        )


@dataclass(frozen=True, slots=True)
class QtileIndicatorView:
    """Pure text renderer suitable for a Qtile polling widget."""

    def text(self, snapshot: IndicatorSnapshot) -> str:
        return _QTILE_TEXT[snapshot.state]


@dataclass(frozen=True, slots=True)
class StatusNotifierItemView:
    """Map authoritative snapshots to Freedesktop StatusNotifierItem fields."""

    def present(self, snapshot: IndicatorSnapshot) -> StatusNotifierPresentation:
        if snapshot.state is IndicatorState.RECORDING:
            status = "NeedsAttention"
        elif snapshot.state in {IndicatorState.OFF, IndicatorState.UNAVAILABLE}:
            status = "Passive"
        else:
            status = "Active"

        backend = snapshot.capture_backend or "none"
        metadata = snapshot.metadata_source or "none"
        last_capture = (
            snapshot.last_capture_at.isoformat()
            if snapshot.last_capture_at is not None
            else "never"
        )
        tooltip = (
            f"{snapshot.state.value}; backend={backend}; metadata={metadata}; "
            f"last_capture={last_capture}"
        )
        return StatusNotifierPresentation(
            status=status,
            icon_name=_ICON_NAME[snapshot.state],
            title="Local Recall",
            tooltip=tooltip,
        )


@dataclass(slots=True)
class IndicatorSurface:
    """One-action desktop controls that always re-query daemon authority."""

    controller: IndicatorController

    def poll(self, *, now: datetime) -> IndicatorSnapshot:
        return self.controller.refresh(now=now)

    def stop(self, *, now: datetime) -> IndicatorSnapshot:
        return self.controller.stop(now=now)

    def privacy_on(self, *, now: datetime) -> IndicatorSnapshot:
        return self.controller.privacy_on(now=now)

    def privacy_off(self, *, now: datetime) -> IndicatorSnapshot:
        return self.controller.privacy_off(now=now)
