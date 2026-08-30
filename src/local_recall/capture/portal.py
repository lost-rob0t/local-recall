"""Desktop-portal authorization boundary for Wayland capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

MAX_PORTAL_SCREENSHOT_BYTES = 512 * 1024 * 1024


class PortalError(RuntimeError):
    """Content-free portal capture failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class PortalPermissionState(StrEnum):
    UNAUTHORIZED = "unauthorized"
    AUTHORIZED = "authorized"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True, repr=False)
class PortalScreenshot:
    """Encoded screenshot payload held in memory only."""

    captured_at: datetime
    image_format: str
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("portal screenshot timestamp must be timezone-aware")
        if not self.image_format:
            raise ValueError("portal screenshot image format is required")

    def __repr__(self) -> str:
        return (
            f"PortalScreenshot(captured_at={self.captured_at!r}, "
            f"image_format={self.image_format!r}, payload_bytes={len(self.payload)})"
        )


@dataclass(frozen=True, slots=True)
class PortalCaptureStatus:
    """Content-free portal capture state for status surfaces."""

    backend_id: str
    permission_state: PortalPermissionState
    authorization_model: str
    persistent_sessions: bool
    successful_authorizations: int
    revocations: int
    limitations: tuple[str, ...]


@runtime_checkable
class PortalGateway(Protocol):
    """Transport to a desktop portal daemon; implementations must be content-free."""

    async def request_screenshot(self, *, deadline_monotonic_ns: int) -> PortalScreenshot: ...
