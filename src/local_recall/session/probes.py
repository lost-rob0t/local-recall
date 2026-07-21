from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    DesktopEnvironment,
    DesktopSession,
    DisplayProtocol,
    MetadataCapability,
    MetadataProbeResult,
    ProbeOutcome,
    ProbeReasonCode,
)


@runtime_checkable
class AsyncHealthCheck(Protocol):
    async def __call__(self) -> bool: ...


class GenericXorgMetadataProbe:
    @property
    def source_id(self) -> str:
        return "xorg-generic"

    async def probe(self, session: DesktopSession) -> MetadataProbeResult:
        if session.protocol is not DisplayProtocol.XORG:
            return _incompatible(self.source_id)
        return MetadataProbeResult(
            source_id=self.source_id,
            outcome=ProbeOutcome.HEALTHY,
            reason_code=ProbeReasonCode.AVAILABLE,
            capabilities=frozenset(
                {
                    MetadataCapability.APPLICATION,
                    MetadataCapability.WINDOW_TITLE,
                }
            ),
        )


class QtileMetadataProbe:
    def __init__(self, health_check: AsyncHealthCheck) -> None:
        self._health_check = health_check

    @property
    def source_id(self) -> str:
        return "qtile"

    async def probe(self, session: DesktopSession) -> MetadataProbeResult:
        if (
            session.protocol is not DisplayProtocol.XORG
            or session.desktop is not DesktopEnvironment.QTILE
        ):
            return _incompatible(self.source_id)
        if not await self._health_check():
            return _unavailable(self.source_id)
        return MetadataProbeResult(
            source_id=self.source_id,
            outcome=ProbeOutcome.HEALTHY,
            reason_code=ProbeReasonCode.AVAILABLE,
            capabilities=frozenset(
                {
                    MetadataCapability.APPLICATION,
                    MetadataCapability.WINDOW_TITLE,
                    MetadataCapability.WORKSPACE,
                }
            ),
        )


class ActivityWatchMetadataProbe:
    def __init__(self, health_check: AsyncHealthCheck) -> None:
        self._health_check = health_check

    @property
    def source_id(self) -> str:
        return "activitywatch"

    async def probe(self, session: DesktopSession) -> MetadataProbeResult:
        if session.protocol is DisplayProtocol.UNKNOWN:
            return _incompatible(self.source_id)
        if not await self._health_check():
            return _unavailable(self.source_id)
        return MetadataProbeResult(
            source_id=self.source_id,
            outcome=ProbeOutcome.HEALTHY,
            reason_code=ProbeReasonCode.AVAILABLE,
            capabilities=frozenset(
                {
                    MetadataCapability.APPLICATION,
                    MetadataCapability.ACTIVITY,
                    MetadataCapability.IDLE,
                }
            ),
        )


def _incompatible(source_id: str) -> MetadataProbeResult:
    return MetadataProbeResult(
        source_id=source_id,
        outcome=ProbeOutcome.INCOMPATIBLE,
        reason_code=ProbeReasonCode.INCOMPATIBLE_SESSION,
    )


def _unavailable(source_id: str) -> MetadataProbeResult:
    return MetadataProbeResult(
        source_id=source_id,
        outcome=ProbeOutcome.UNAVAILABLE,
        reason_code=ProbeReasonCode.UNAVAILABLE,
    )
