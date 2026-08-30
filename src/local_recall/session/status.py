from __future__ import annotations

import json

from .models import DisplayProtocol, SessionResolution

_WAYLAND_LIMITATIONS = (
    "window-metadata-unavailable",
    "persistent-sessions-not-used",
    "screencast-streams-not-supported",
    "region-cropping-unavailable",
)


def session_resolution_status(resolution: SessionResolution) -> dict[str, object]:
    status: dict[str, object] = {
        "capture_backend": resolution.capture_backend_id,
        "desktop": resolution.session.desktop.value,
        "metadata_sources": list(resolution.selected_metadata_sources),
        "probes": [
            {
                "capabilities": sorted(capability.value for capability in probe.capabilities),
                "outcome": probe.outcome.value,
                "reason": probe.reason_code.value,
                "source": probe.source_id,
            }
            for probe in resolution.probe_results
        ],
        "protocol": resolution.session.protocol.value,
        "reason": resolution.reason_code.value,
        "recording_supported": resolution.recording_supported,
        "session_confidence": resolution.session.confidence,
        "session_reason": resolution.session.reason_code.value,
    }
    if resolution.session.protocol is DisplayProtocol.WAYLAND:
        status["wayland"] = {
            "authorization": "portal-per-capture",
            "limitations": list(_WAYLAND_LIMITATIONS),
            "persistent_sessions": False,
        }
    return status


def render_session_resolution_status(resolution: SessionResolution) -> str:
    return json.dumps(session_resolution_status(resolution), sort_keys=True)
