"""Daemon-authoritative, content-free recording indicator domain model."""

from enum import StrEnum


class IndicatorState(StrEnum):
    """Closed display states safe for desktop status surfaces."""

    OFF = "off"
    PAUSED = "paused"
    RECORDING = "recording"
    PRIVACY = "privacy"
    LOCKED = "locked"
    OVERLOADED = "overloaded"
    FAULTED = "faulted"
    UNAVAILABLE = "unavailable"
