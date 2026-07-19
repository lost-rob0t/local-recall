from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from .detection import EnvironmentSnapshot, detect_desktop_session
from .models import (
    DesktopSession,
    DisplayProtocol,
    MetadataProbeResult,
    ProbeOutcome,
    ProbeReasonCode,
    ResolutionReasonCode,
    SessionResolution,
)


@runtime_checkable
class MetadataStrategyProbe(Protocol):
    @property
    def source_id(self) -> str: ...

    async def probe(self, session: DesktopSession) -> MetadataProbeResult: ...


class SessionResolver:
    def __init__(
        self,
        probes: Iterable[MetadataStrategyProbe],
        *,
        generic_xorg_probe: MetadataStrategyProbe | None,
        probe_timeout_seconds: float = 1.0,
    ) -> None:
        if probe_timeout_seconds <= 0.0:
            raise ValueError("probe timeout must be positive")
        registry: dict[str, MetadataStrategyProbe] = {}
        for probe in probes:
            if probe.source_id in registry:
                raise ValueError("metadata probe identifiers must be unique")
            registry[probe.source_id] = probe
        if generic_xorg_probe is not None:
            if generic_xorg_probe.source_id != "xorg-generic":
                raise ValueError("generic Xorg probe must use xorg-generic identifier")
            if generic_xorg_probe.source_id in registry:
                raise ValueError("metadata probe identifiers must be unique")
            registry[generic_xorg_probe.source_id] = generic_xorg_probe
        self._registry = registry
        self._generic_xorg_probe = generic_xorg_probe
        self._probe_timeout_seconds = probe_timeout_seconds

    async def resolve(
        self,
        environment: EnvironmentSnapshot,
        enabled_sources: tuple[str, ...],
    ) -> SessionResolution:
        session = detect_desktop_session(environment)
        if session.protocol is DisplayProtocol.UNKNOWN:
            return SessionResolution(
                session=session,
                recording_supported=False,
                capture_backend_id=None,
                selected_metadata_sources=(),
                probe_results=(),
                reason_code=ResolutionReasonCode.UNKNOWN_SESSION,
            )
        if session.protocol is DisplayProtocol.WAYLAND:
            return SessionResolution(
                session=session,
                recording_supported=False,
                capture_backend_id=None,
                selected_metadata_sources=(),
                probe_results=(),
                reason_code=ResolutionReasonCode.UNSUPPORTED_SESSION,
            )

        results: list[MetadataProbeResult] = []
        selected: list[str] = []
        for source_id in enabled_sources:
            item = await self._probe_source(source_id, session)
            results.append(item)
            if item.outcome is ProbeOutcome.HEALTHY:
                selected.append(item.source_id)

        if (
            enabled_sources
            and not selected
            and self._generic_xorg_probe is not None
            and self._generic_xorg_probe.source_id not in enabled_sources
        ):
            fallback = await self._probe_source(
                self._generic_xorg_probe.source_id,
                session,
            )
            results.append(fallback)
            if fallback.outcome is ProbeOutcome.HEALTHY:
                selected.append(fallback.source_id)

        if not selected:
            return SessionResolution(
                session=session,
                recording_supported=False,
                capture_backend_id=None,
                selected_metadata_sources=(),
                probe_results=tuple(results),
                reason_code=ResolutionReasonCode.NO_HEALTHY_METADATA,
            )

        return SessionResolution(
            session=session,
            recording_supported=True,
            capture_backend_id="xorg-generic",
            selected_metadata_sources=tuple(selected),
            probe_results=tuple(results),
            reason_code=ResolutionReasonCode.READY,
        )

    async def _probe_source(
        self,
        source_id: str,
        session: DesktopSession,
    ) -> MetadataProbeResult:
        probe = self._registry.get(source_id)
        if probe is None:
            return MetadataProbeResult(
                source_id=_safe_source_id(source_id),
                outcome=ProbeOutcome.UNKNOWN_SOURCE,
                reason_code=ProbeReasonCode.UNKNOWN_SOURCE,
            )
        try:
            result = await asyncio.wait_for(
                probe.probe(session),
                timeout=self._probe_timeout_seconds,
            )
        except TimeoutError:
            return MetadataProbeResult(
                source_id=_safe_source_id(source_id),
                outcome=ProbeOutcome.TIMED_OUT,
                reason_code=ProbeReasonCode.PROBE_TIMED_OUT,
            )
        except Exception:
            return MetadataProbeResult(
                source_id=_safe_source_id(source_id),
                outcome=ProbeOutcome.FAILED,
                reason_code=ProbeReasonCode.PROBE_FAILED,
            )
        if result.source_id != source_id:
            return MetadataProbeResult(
                source_id=_safe_source_id(source_id),
                outcome=ProbeOutcome.FAILED,
                reason_code=ProbeReasonCode.INVALID_PROBE_RESULT,
            )
        return result


def _safe_source_id(source_id: str) -> str:
    normalized = source_id.strip().lower()
    if normalized and normalized[0].isalpha() and all(
        character.isalnum() or character in "_.-" for character in normalized
    ):
        return normalized[:128]
    return "invalid-source"
