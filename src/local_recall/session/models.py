from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class DisplayProtocol(StrEnum):
    XORG = "xorg"
    WAYLAND = "wayland"
    UNKNOWN = "unknown"


class DesktopEnvironment(StrEnum):
    QTILE = "qtile"
    GNOME = "gnome"
    KDE = "kde"
    SWAY = "sway"
    XFCE = "xfce"
    COSMIC = "cosmic"
    UNKNOWN = "unknown"


class SessionReasonCode(StrEnum):
    DETECTED = "detected"
    MISSING_SESSION_TYPE = "missing-session-type"
    UNKNOWN_SESSION_TYPE = "unknown-session-type"
    MISSING_DISPLAY = "missing-display"
    CONFLICTING_EVIDENCE = "conflicting-evidence"


class MetadataCapability(StrEnum):
    APPLICATION = "application"
    LAYOUT = "layout"
    SCREEN = "screen"
    WINDOW_TITLE = "window-title"
    WORKSPACE = "workspace"
    ACTIVITY = "activity"
    IDLE = "idle"
    DOMAIN = "domain"


class ProbeOutcome(StrEnum):
    HEALTHY = "healthy"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    UNKNOWN_SOURCE = "unknown-source"


class ProbeReasonCode(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE_SESSION = "incompatible-session"
    PROBE_FAILED = "probe-failed"
    PROBE_TIMED_OUT = "probe-timed-out"
    INVALID_PROBE_RESULT = "invalid-probe-result"
    UNKNOWN_SOURCE = "unknown-source"


class ResolutionReasonCode(StrEnum):
    READY = "ready"
    UNKNOWN_SESSION = "unknown-session"
    UNSUPPORTED_SESSION = "unsupported-session"
    NO_HEALTHY_METADATA = "no-healthy-metadata"


@dataclass(frozen=True, slots=True)
class DesktopSession:
    protocol: DisplayProtocol
    desktop: DesktopEnvironment
    confidence: float
    reason_code: SessionReasonCode

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("session confidence must be between 0 and 1")
        if self.protocol is DisplayProtocol.UNKNOWN and self.confidence != 0.0:
            raise ValueError("unknown sessions must have zero confidence")


@dataclass(frozen=True, slots=True)
class MetadataProbeResult:
    source_id: str
    outcome: ProbeOutcome
    reason_code: ProbeReasonCode
    capabilities: frozenset[MetadataCapability] = frozenset()

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.source_id):
            raise ValueError("metadata source identifier is invalid")
        if self.outcome is ProbeOutcome.HEALTHY and not self.capabilities:
            raise ValueError("healthy metadata probes require capabilities")
        if self.outcome is not ProbeOutcome.HEALTHY and self.capabilities:
            raise ValueError("unhealthy metadata probes cannot advertise capabilities")


@dataclass(frozen=True, slots=True)
class SessionResolution:
    session: DesktopSession
    recording_supported: bool
    capture_backend_id: str | None
    selected_metadata_sources: tuple[str, ...]
    probe_results: tuple[MetadataProbeResult, ...]
    reason_code: ResolutionReasonCode

    def __post_init__(self) -> None:
        if self.capture_backend_id is not None and not _IDENTIFIER.fullmatch(
            self.capture_backend_id
        ):
            raise ValueError("capture backend identifier is invalid")
        if len(set(self.selected_metadata_sources)) != len(self.selected_metadata_sources):
            raise ValueError("selected metadata source identifiers must be unique")
        if any(
            not _IDENTIFIER.fullmatch(source_id) for source_id in self.selected_metadata_sources
        ):
            raise ValueError("selected metadata source identifier is invalid")
        if self.recording_supported:
            if self.capture_backend_id is None:
                raise ValueError("supported recording requires a capture backend")
            if not self.selected_metadata_sources:
                raise ValueError("supported recording requires metadata sources")
            if self.reason_code is not ResolutionReasonCode.READY:
                raise ValueError("supported recording requires ready resolution")
        elif self.capture_backend_id is not None:
            raise ValueError("unsupported recording cannot select a capture backend")
