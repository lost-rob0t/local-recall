from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from local_recall.session import (
    DesktopSession,
    EnvironmentSnapshot,
    MetadataCapability,
    MetadataProbeResult,
    ProbeOutcome,
    ProbeReasonCode,
    ResolutionReasonCode,
    SessionResolver,
)

from .harness import AdvanceClock, DesktopWindow, LocalRecallSystem, SyntheticDesktop

_NOW = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)


class QtileProbe:
    source_id = "qtile"

    async def probe(self, session: DesktopSession) -> MetadataProbeResult:
        del session
        return MetadataProbeResult(
            source_id="qtile",
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


class GenericXorgProbe:
    source_id = "xorg-generic"

    async def probe(self, session: DesktopSession) -> MetadataProbeResult:
        del session
        return MetadataProbeResult(
            source_id="xorg-generic",
            outcome=ProbeOutcome.HEALTHY,
            reason_code=ProbeReasonCode.AVAILABLE,
            capabilities=frozenset(
                {MetadataCapability.APPLICATION, MetadataCapability.WINDOW_TITLE}
            ),
        )


def test_qtile_metadata_is_preferred_over_generic_xorg(tmp_path: Path) -> None:
    resolver = SessionResolver(
        (QtileProbe(),), generic_xorg_probe=GenericXorgProbe(), probe_timeout_seconds=1.0
    )
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
            "XDG_CURRENT_DESKTOP": "Qtile",
        }
    )

    resolution = asyncio.run(resolver.resolve(snapshot, ("qtile",)))

    assert resolution.reason_code is ResolutionReasonCode.READY
    assert resolution.capture_backend_id == "xorg-generic"
    assert resolution.selected_metadata_sources == ("qtile",)


def test_generic_xorg_fallback_when_qtile_is_unavailable(tmp_path: Path) -> None:
    resolver = SessionResolver(
        (QtileProbe(),), generic_xorg_probe=GenericXorgProbe(), probe_timeout_seconds=1.0
    )
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
            "XDG_CURRENT_DESKTOP": "Qtile",
        }
    )

    resolution = asyncio.run(resolver.resolve(snapshot, ("broken",)))

    assert resolution.reason_code is ResolutionReasonCode.READY
    assert resolution.selected_metadata_sources == ("xorg-generic",)


def test_synthetic_desktop_session_records_metadata_into_persisted_records(
    tmp_path: Path,
) -> None:
    clock = AdvanceClock(_NOW)
    system = LocalRecallSystem(
        root=tmp_path,
        clock=clock,
        desktop=SyntheticDesktop(
            clock=clock.now,
            windows=[DesktopWindow("emacs", "roadmap-notes")],
        ),
    )
    try:
        system.start()
        system.wait_recording()
        record = asyncio.run(system.capture_once())
        metadata = record.frame.metadata
        assert metadata.get("application") == "emacs"
        assert metadata.get("window.title") == "roadmap-notes"
        assert metadata.get("workspace") == "ws-1"
        provenance = record.frame.metadata.fields[0].provenance
        assert provenance is not None
        assert provenance[0].source_id == "synthetic-desktop"
        assert system.last_raw_frame is not None
        provenance = system.last_raw_frame.capture_provenance
        assert provenance is not None
        assert provenance.backend_id == "synthetic-capture"
    finally:
        system.shutdown()
