from __future__ import annotations

import asyncio

from local_recall.session import (
    ActivityWatchMetadataProbe,
    DesktopEnvironment,
    DesktopSession,
    DisplayProtocol,
    MetadataCapability,
    ProbeOutcome,
    SessionReasonCode,
)


class SyntheticCapabilitySource:
    def __init__(self, capabilities: frozenset[str]) -> None:
        self._capabilities = capabilities

    async def probe_capabilities(self) -> frozenset[str]:
        return self._capabilities


def xorg_session() -> DesktopSession:
    return DesktopSession(
        protocol=DisplayProtocol.XORG,
        desktop=DesktopEnvironment.QTILE,
        confidence=1.0,
        reason_code=SessionReasonCode.DETECTED,
    )


def test_activitywatch_probe_reports_discovered_capabilities() -> None:
    probe = ActivityWatchMetadataProbe(
        SyntheticCapabilitySource(
            frozenset(
                {
                    "application",
                    "window-title",
                    "activity",
                    "idle",
                    "domain",
                }
            )
        )
    )

    result = asyncio.run(probe.probe(xorg_session()))

    assert result.outcome is ProbeOutcome.HEALTHY
    assert result.capabilities == frozenset(
        {
            MetadataCapability.APPLICATION,
            MetadataCapability.WINDOW_TITLE,
            MetadataCapability.ACTIVITY,
            MetadataCapability.IDLE,
            MetadataCapability.DOMAIN,
        }
    )


def test_activitywatch_probe_with_no_usable_capability_is_unavailable() -> None:
    probe = ActivityWatchMetadataProbe(SyntheticCapabilitySource(frozenset()))

    result = asyncio.run(probe.probe(xorg_session()))

    assert result.outcome is ProbeOutcome.UNAVAILABLE
    assert result.capabilities == frozenset()


def test_activitywatch_probe_keeps_legacy_health_check_contract() -> None:
    async def healthy() -> bool:
        return True

    probe = ActivityWatchMetadataProbe(healthy)

    result = asyncio.run(probe.probe(xorg_session()))

    assert result.outcome is ProbeOutcome.HEALTHY
    assert result.capabilities == frozenset(
        {
            MetadataCapability.APPLICATION,
            MetadataCapability.ACTIVITY,
            MetadataCapability.IDLE,
        }
    )
