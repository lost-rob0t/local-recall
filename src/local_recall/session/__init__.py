"""Desktop-session detection and metadata-strategy resolution."""

from .coordinator import compose_context_metadata
from .detection import EnvironmentSnapshot, detect_desktop_session
from .models import (
    DesktopEnvironment,
    DesktopSession,
    DisplayProtocol,
    MetadataCapability,
    MetadataProbeResult,
    ProbeOutcome,
    ProbeReasonCode,
    ResolutionReasonCode,
    SessionReasonCode,
    SessionResolution,
)
from .resolver import MetadataStrategyProbe, SessionResolver

__all__ = [
    "DesktopEnvironment",
    "DesktopSession",
    "DisplayProtocol",
    "EnvironmentSnapshot",
    "MetadataCapability",
    "MetadataProbeResult",
    "MetadataStrategyProbe",
    "ProbeOutcome",
    "ProbeReasonCode",
    "ResolutionReasonCode",
    "SessionReasonCode",
    "SessionResolution",
    "SessionResolver",
    "compose_context_metadata",
    "detect_desktop_session",
]
