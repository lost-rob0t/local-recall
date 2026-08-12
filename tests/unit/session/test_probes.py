import asyncio

from local_recall.session import (
    ActivityWatchMetadataProbe,
    DesktopEnvironment,
    DesktopSession,
    DisplayProtocol,
    GenericXorgMetadataProbe,
    MetadataCapability,
    ProbeOutcome,
    ProbeReasonCode,
    QtileMetadataProbe,
    SessionReasonCode,
)


class FixedHealth:
    def __init__(self, healthy: bool) -> None:
        self._healthy = healthy
        self.calls = 0

    async def __call__(self) -> bool:
        self.calls += 1
        return self._healthy


def session(
    protocol: DisplayProtocol = DisplayProtocol.XORG,
    desktop: DesktopEnvironment = DesktopEnvironment.QTILE,
) -> DesktopSession:
    return DesktopSession(
        protocol=protocol,
        desktop=desktop,
        confidence=1.0,
        reason_code=SessionReasonCode.DETECTED,
    )


def test_qtile_probe_checks_health_only_for_compatible_qtile_xorg() -> None:
    health = FixedHealth(True)
    probe = QtileMetadataProbe(health)

    result = asyncio.run(probe.probe(session()))

    assert result.outcome is ProbeOutcome.HEALTHY
    assert result.capabilities == frozenset(
        {
            MetadataCapability.APPLICATION,
            MetadataCapability.WINDOW_TITLE,
            MetadataCapability.WORKSPACE,
        }
    )
    assert health.calls == 1


def test_qtile_probe_rejects_non_qtile_session_without_health_call() -> None:
    health = FixedHealth(True)
    probe = QtileMetadataProbe(health)

    result = asyncio.run(probe.probe(session(desktop=DesktopEnvironment.GNOME)))

    assert result.outcome is ProbeOutcome.INCOMPATIBLE
    assert result.reason_code is ProbeReasonCode.INCOMPATIBLE_SESSION
    assert health.calls == 0


def test_activitywatch_probe_reports_unavailable_health() -> None:
    health = FixedHealth(False)
    probe = ActivityWatchMetadataProbe(health)

    result = asyncio.run(probe.probe(session()))

    assert result.outcome is ProbeOutcome.UNAVAILABLE
    assert result.reason_code is ProbeReasonCode.UNAVAILABLE
    assert health.calls == 1


def test_activitywatch_probe_supports_wayland_metadata_without_enabling_capture() -> None:
    health = FixedHealth(True)
    probe = ActivityWatchMetadataProbe(health)

    result = asyncio.run(
        probe.probe(
            session(
                protocol=DisplayProtocol.WAYLAND,
                desktop=DesktopEnvironment.SWAY,
            )
        )
    )

    assert result.outcome is ProbeOutcome.HEALTHY
    assert MetadataCapability.ACTIVITY in result.capabilities


def test_generic_xorg_probe_requires_operational_reader_capability() -> None:
    health = FixedHealth(False)
    probe = GenericXorgMetadataProbe(health)

    result = asyncio.run(probe.probe(session()))

    assert result.outcome is ProbeOutcome.UNAVAILABLE
    assert result.reason_code is ProbeReasonCode.UNAVAILABLE
    assert result.capabilities == frozenset()
    assert health.calls == 1


def test_generic_xorg_probe_does_not_read_content() -> None:
    health = FixedHealth(True)
    probe = GenericXorgMetadataProbe(health)

    result = asyncio.run(probe.probe(session()))

    assert result.outcome is ProbeOutcome.HEALTHY
    assert result.capabilities == frozenset(
        {
            MetadataCapability.APPLICATION,
            MetadataCapability.WINDOW_TITLE,
            MetadataCapability.WORKSPACE,
        }
    )
    assert health.calls == 1
