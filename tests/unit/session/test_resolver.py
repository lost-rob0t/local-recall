import asyncio
from collections.abc import Awaitable, Callable

from local_recall.session import (
    DesktopSession,
    EnvironmentSnapshot,
    MetadataCapability,
    MetadataProbeResult,
    MetadataStrategyProbe,
    ProbeOutcome,
    ProbeReasonCode,
    ResolutionReasonCode,
    SessionResolver,
)


class SyntheticProbe:
    def __init__(
        self,
        source_id: str,
        result_factory: Callable[[DesktopSession], Awaitable[MetadataProbeResult]],
    ) -> None:
        self._source_id = source_id
        self._result_factory = result_factory

    @property
    def source_id(self) -> str:
        return self._source_id

    async def probe(self, session: DesktopSession) -> MetadataProbeResult:
        return await self._result_factory(session)


async def result(
    source_id: str,
    outcome: ProbeOutcome,
    reason_code: ProbeReasonCode,
    capabilities: frozenset[MetadataCapability] = frozenset(),
) -> MetadataProbeResult:
    return MetadataProbeResult(
        source_id=source_id,
        outcome=outcome,
        reason_code=reason_code,
        capabilities=capabilities,
    )


def probe(
    source_id: str,
    outcome: ProbeOutcome = ProbeOutcome.HEALTHY,
    reason_code: ProbeReasonCode = ProbeReasonCode.AVAILABLE,
    capabilities: frozenset[MetadataCapability] = frozenset(),
) -> MetadataStrategyProbe:
    async def factory(_: DesktopSession) -> MetadataProbeResult:
        return await result(source_id, outcome, reason_code, capabilities)

    return SyntheticProbe(source_id, factory)


def qtile_xorg() -> EnvironmentSnapshot:
    return EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
            "XDG_CURRENT_DESKTOP": "Qtile",
        }
    )


def test_composes_healthy_sources_in_configured_order() -> None:
    qtile = probe(
        "qtile",
        capabilities=frozenset(
            {
                MetadataCapability.APPLICATION,
                MetadataCapability.WINDOW_TITLE,
                MetadataCapability.WORKSPACE,
            }
        ),
    )
    activitywatch = probe(
        "activitywatch",
        capabilities=frozenset({MetadataCapability.APPLICATION, MetadataCapability.ACTIVITY}),
    )
    generic = probe(
        "xorg-generic",
        capabilities=frozenset({MetadataCapability.APPLICATION, MetadataCapability.WINDOW_TITLE}),
    )
    resolver = SessionResolver((qtile, activitywatch), generic_xorg_probe=generic)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("qtile", "activitywatch")))

    assert resolution.recording_supported is True
    assert resolution.capture_backend_id == "xorg-generic"
    assert resolution.selected_metadata_sources == ("qtile", "activitywatch")
    assert resolution.reason_code is ResolutionReasonCode.READY


def test_selects_activitywatch_as_a_single_healthy_source() -> None:
    activitywatch = probe(
        "activitywatch",
        capabilities=frozenset({MetadataCapability.APPLICATION, MetadataCapability.ACTIVITY}),
    )
    resolver = SessionResolver((activitywatch,), generic_xorg_probe=None)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("activitywatch",)))

    assert resolution.recording_supported is True
    assert resolution.selected_metadata_sources == ("activitywatch",)


def test_selects_explicit_generic_xorg_source() -> None:
    generic = probe(
        "xorg-generic",
        capabilities=frozenset({MetadataCapability.APPLICATION, MetadataCapability.WINDOW_TITLE}),
    )
    resolver = SessionResolver((), generic_xorg_probe=generic)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("xorg-generic",)))

    assert resolution.recording_supported is True
    assert resolution.selected_metadata_sources == ("xorg-generic",)


def test_falls_back_to_generic_xorg_when_specialized_probe_is_unavailable() -> None:
    qtile = probe(
        "qtile",
        outcome=ProbeOutcome.UNAVAILABLE,
        reason_code=ProbeReasonCode.UNAVAILABLE,
    )
    generic = probe(
        "xorg-generic",
        capabilities=frozenset({MetadataCapability.APPLICATION, MetadataCapability.WINDOW_TITLE}),
    )
    resolver = SessionResolver((qtile,), generic_xorg_probe=generic)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("qtile",)))

    assert resolution.recording_supported is True
    assert resolution.selected_metadata_sources == ("xorg-generic",)
    assert tuple(item.source_id for item in resolution.probe_results) == (
        "qtile",
        "xorg-generic",
    )


def test_wayland_session_never_silently_selects_xorg_capture() -> None:
    generic = probe("xorg-generic")
    resolver = SessionResolver((), generic_xorg_probe=generic)
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "wayland",
            "WAYLAND_DISPLAY": "wayland-1",
            "XDG_CURRENT_DESKTOP": "sway",
        }
    )

    resolution = asyncio.run(resolver.resolve(snapshot, ("xorg-generic",)))

    assert resolution.recording_supported is False
    assert resolution.capture_backend_id is None
    assert resolution.selected_metadata_sources == ()
    assert resolution.reason_code is ResolutionReasonCode.UNSUPPORTED_SESSION


def test_unsupported_session_does_not_run_metadata_probes() -> None:
    async def must_not_run(_: DesktopSession) -> MetadataProbeResult:
        raise AssertionError("metadata probe ran for unsupported session")

    resolver = SessionResolver(
        (SyntheticProbe("activitywatch", must_not_run),),
        generic_xorg_probe=None,
    )
    snapshot = EnvironmentSnapshot.from_mapping(
        {"XDG_SESSION_TYPE": "wayland", "WAYLAND_DISPLAY": "wayland-1"}
    )

    resolution = asyncio.run(resolver.resolve(snapshot, ("activitywatch",)))

    assert resolution.recording_supported is False
    assert resolution.probe_results == ()


def test_probe_exception_is_replaced_with_fixed_sanitized_result() -> None:
    marker = "synthetic-sensitive-probe-error"

    async def fail(_: DesktopSession) -> MetadataProbeResult:
        raise RuntimeError(marker)

    resolver = SessionResolver(
        (SyntheticProbe("qtile", fail),),
        generic_xorg_probe=None,
    )

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("qtile",)))

    assert resolution.recording_supported is False
    assert resolution.probe_results[0].outcome is ProbeOutcome.FAILED
    assert resolution.probe_results[0].reason_code is ProbeReasonCode.PROBE_FAILED
    assert marker not in repr(resolution)


def test_probe_timeout_is_bounded_and_sanitized() -> None:
    async def block(_: DesktopSession) -> MetadataProbeResult:
        await asyncio.sleep(1.0)
        raise AssertionError("unreachable")

    resolver = SessionResolver(
        (SyntheticProbe("activitywatch", block),),
        generic_xorg_probe=None,
        probe_timeout_seconds=0.01,
    )

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("activitywatch",)))

    assert resolution.probe_results[0].outcome is ProbeOutcome.TIMED_OUT
    assert resolution.probe_results[0].reason_code is ProbeReasonCode.PROBE_TIMED_OUT


def test_unknown_configured_source_is_reported_without_dynamic_import() -> None:
    resolver = SessionResolver((), generic_xorg_probe=None)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("unknown-source",)))

    assert resolution.recording_supported is False
    assert resolution.probe_results[0].outcome is ProbeOutcome.UNKNOWN_SOURCE
    assert resolution.probe_results[0].reason_code is ProbeReasonCode.UNKNOWN_SOURCE


def test_unknown_source_value_is_sanitized() -> None:
    marker = "synthetic-sensitive-source"
    resolver = SessionResolver((), generic_xorg_probe=None)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), (f"../../{marker}",)))

    assert resolution.probe_results[0].source_id == "invalid-source"
    assert marker not in repr(resolution)


def test_mismatched_probe_identity_is_rejected() -> None:
    async def mismatched(_: DesktopSession) -> MetadataProbeResult:
        return await result(
            "activitywatch",
            ProbeOutcome.HEALTHY,
            ProbeReasonCode.AVAILABLE,
            frozenset({MetadataCapability.APPLICATION}),
        )

    resolver = SessionResolver(
        (SyntheticProbe("qtile", mismatched),),
        generic_xorg_probe=None,
    )

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("qtile",)))

    assert resolution.recording_supported is False
    assert resolution.probe_results[0].reason_code is ProbeReasonCode.INVALID_PROBE_RESULT


def test_empty_configured_sources_do_not_enable_implicit_fallback() -> None:
    generic = probe("xorg-generic")
    resolver = SessionResolver((), generic_xorg_probe=generic)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ()))

    assert resolution.recording_supported is False
    assert resolution.selected_metadata_sources == ()
    assert resolution.reason_code is ResolutionReasonCode.NO_HEALTHY_METADATA


def wayland_snapshot() -> EnvironmentSnapshot:
    return EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "wayland",
            "WAYLAND_DISPLAY": "wayland-1",
            "XDG_CURRENT_DESKTOP": "sway",
        }
    )


def portal_probe(
    outcome: ProbeOutcome = ProbeOutcome.HEALTHY,
    reason_code: ProbeReasonCode = ProbeReasonCode.AVAILABLE,
) -> MetadataStrategyProbe:
    return probe(
        "wayland-portal",
        outcome=outcome,
        reason_code=reason_code,
        capabilities=frozenset({MetadataCapability.SCREEN}),
    )


def test_wayland_portal_probe_enables_portal_capture_without_metadata_sources() -> None:
    portal = portal_probe()
    resolver = SessionResolver((), generic_xorg_probe=None, wayland_portal_probe=portal)

    resolution = asyncio.run(resolver.resolve(wayland_snapshot(), ()))

    assert resolution.recording_supported is True
    assert resolution.capture_backend_id == "wayland-portal"
    assert resolution.selected_metadata_sources == ()
    assert resolution.reason_code is ResolutionReasonCode.READY
    assert resolution.probe_results[-1].source_id == "wayland-portal"
    assert resolution.probe_results[-1].outcome is ProbeOutcome.HEALTHY


def test_wayland_portal_capture_includes_healthy_metadata_sources() -> None:
    portal = portal_probe()
    activitywatch = probe(
        "activitywatch",
        capabilities=frozenset({MetadataCapability.APPLICATION, MetadataCapability.ACTIVITY}),
    )
    resolver = SessionResolver(
        (activitywatch,), generic_xorg_probe=None, wayland_portal_probe=portal
    )

    resolution = asyncio.run(resolver.resolve(wayland_snapshot(), ("activitywatch",)))

    assert resolution.recording_supported is True
    assert resolution.capture_backend_id == "wayland-portal"
    assert resolution.selected_metadata_sources == ("activitywatch",)


def test_unhealthy_wayland_portal_probe_reports_portal_unavailable() -> None:
    portal = portal_probe(ProbeOutcome.UNAVAILABLE, ProbeReasonCode.UNAVAILABLE)
    resolver = SessionResolver((), generic_xorg_probe=None, wayland_portal_probe=portal)

    resolution = asyncio.run(resolver.resolve(wayland_snapshot(), ()))

    assert resolution.recording_supported is False
    assert resolution.capture_backend_id is None
    assert resolution.reason_code is ResolutionReasonCode.PORTAL_UNAVAILABLE


def test_wayland_portal_probe_failure_is_sanitized() -> None:
    marker = "synthetic-sensitive-portal-marker"

    async def fail(_: DesktopSession) -> MetadataProbeResult:
        raise RuntimeError(marker)

    portal = SyntheticProbe("wayland-portal", fail)
    resolver = SessionResolver((), generic_xorg_probe=None, wayland_portal_probe=portal)

    resolution = asyncio.run(resolver.resolve(wayland_snapshot(), ()))

    assert resolution.recording_supported is False
    assert resolution.probe_results[-1].outcome is ProbeOutcome.FAILED
    assert resolution.reason_code is ResolutionReasonCode.PORTAL_UNAVAILABLE
    assert marker not in repr(resolution)


def test_wayland_portal_probe_timeout_is_bounded() -> None:
    async def block(_: DesktopSession) -> MetadataProbeResult:
        await asyncio.sleep(1.0)
        raise AssertionError("unreachable")

    portal = SyntheticProbe("wayland-portal", block)
    resolver = SessionResolver(
        (), generic_xorg_probe=None, wayland_portal_probe=portal, probe_timeout_seconds=0.01
    )

    resolution = asyncio.run(resolver.resolve(wayland_snapshot(), ()))

    assert resolution.probe_results[-1].outcome is ProbeOutcome.TIMED_OUT
    assert resolution.reason_code is ResolutionReasonCode.PORTAL_UNAVAILABLE


def test_wayland_portal_probe_is_ignored_on_xorg_sessions() -> None:
    portal = portal_probe()
    generic = probe(
        "xorg-generic",
        capabilities=frozenset({MetadataCapability.APPLICATION, MetadataCapability.WINDOW_TITLE}),
    )
    resolver = SessionResolver((), generic_xorg_probe=generic, wayland_portal_probe=portal)

    resolution = asyncio.run(resolver.resolve(qtile_xorg(), ("xorg-generic",)))

    assert resolution.recording_supported is True
    assert resolution.capture_backend_id == "xorg-generic"
    assert all(item.source_id != "wayland-portal" for item in resolution.probe_results)


def test_wayland_portal_probe_requires_dedicated_identifier() -> None:
    portal = probe("qtile")
    try:
        SessionResolver((), generic_xorg_probe=None, wayland_portal_probe=portal)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid portal probe identifier was accepted")
