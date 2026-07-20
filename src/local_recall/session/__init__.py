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
from .probes import (
    ActivityWatchMetadataProbe,
    AsyncHealthCheck,
    GenericXorgMetadataProbe,
    QtileMetadataProbe,
)
from .resolver import MetadataStrategyProbe, SessionResolver
from .status import render_session_resolution_status, session_resolution_status

__all__ = [
    "ActivityWatchMetadataProbe",
    "AsyncHealthCheck",
    "DesktopEnvironment",
    "DesktopSession",
    "DisplayProtocol",
    "EnvironmentSnapshot",
    "GenericXorgMetadataProbe",
    "MetadataCapability",
    "MetadataProbeResult",
    "MetadataStrategyProbe",
    "ProbeOutcome",
    "ProbeReasonCode",
    "QtileMetadataProbe",
    "ResolutionReasonCode",
    "SessionReasonCode",
    "SessionResolution",
    "SessionResolver",
    "compose_context_metadata",
    "detect_desktop_session",
    "render_session_resolution_status",
    "session_resolution_status",
]
