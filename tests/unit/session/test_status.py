from __future__ import annotations

import json

from local_recall.session import (
    DesktopEnvironment,
    DesktopSession,
    DisplayProtocol,
    ResolutionReasonCode,
    SessionReasonCode,
    SessionResolution,
    render_session_resolution_status,
    session_resolution_status,
)


def _resolution(
    *, protocol: DisplayProtocol, backend: str | None, supported: bool
) -> SessionResolution:
    session = DesktopSession(
        protocol=protocol,
        desktop=DesktopEnvironment.SWAY
        if protocol is DisplayProtocol.WAYLAND
        else DesktopEnvironment.QTILE,
        confidence=1.0,
        reason_code=SessionReasonCode.DETECTED,
    )
    return SessionResolution(
        session=session,
        recording_supported=supported,
        capture_backend_id=backend,
        selected_metadata_sources=(),
        probe_results=(),
        reason_code=ResolutionReasonCode.READY
        if supported
        else (ResolutionReasonCode.PORTAL_UNAVAILABLE),
    )


def test_wayland_resolution_surfaces_limitations_in_status() -> None:
    resolution = _resolution(
        protocol=DisplayProtocol.WAYLAND, backend="wayland-portal", supported=True
    )

    status = session_resolution_status(resolution)

    wayland = status["wayland"]
    assert isinstance(wayland, dict)
    assert wayland["authorization"] == "portal-per-capture"
    assert wayland["persistent_sessions"] is False
    assert "window-metadata-unavailable" in wayland["limitations"]
    assert "screencast-streams-not-supported" in wayland["limitations"]
    rendered = render_session_resolution_status(resolution)
    parsed = json.loads(rendered)
    assert parsed["wayland"]["persistent_sessions"] is False


def test_xorg_resolution_has_no_wayland_block() -> None:
    resolution = _resolution(protocol=DisplayProtocol.XORG, backend="xorg-generic", supported=True)

    status = session_resolution_status(resolution)

    assert "wayland" not in status
