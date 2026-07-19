from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from .models import (
    DesktopEnvironment,
    DesktopSession,
    DisplayProtocol,
    SessionReasonCode,
)

_DESKTOP_ALIASES = {
    "cosmic": DesktopEnvironment.COSMIC,
    "gnome": DesktopEnvironment.GNOME,
    "kde": DesktopEnvironment.KDE,
    "plasma": DesktopEnvironment.KDE,
    "qtile": DesktopEnvironment.QTILE,
    "sway": DesktopEnvironment.SWAY,
    "xfce": DesktopEnvironment.XFCE,
    "xfce4": DesktopEnvironment.XFCE,
}
_TOKEN_SEPARATOR = re.compile(r"[,:;+\s]+")


@dataclass(frozen=True, slots=True)
class EnvironmentSnapshot:
    session_type: DisplayProtocol | None
    session_type_present: bool
    display_present: bool
    wayland_display_present: bool
    desktop_candidates: frozenset[DesktopEnvironment]

    @classmethod
    def from_mapping(cls, environment: Mapping[str, str]) -> EnvironmentSnapshot:
        raw_session_type = environment.get("XDG_SESSION_TYPE")
        session_type_present = raw_session_type is not None and bool(
            raw_session_type.strip()
        )
        session_type = _normalize_session_type(raw_session_type)
        desktop_candidates = _known_desktops(
            environment.get("XDG_CURRENT_DESKTOP"),
            environment.get("DESKTOP_SESSION"),
        )
        return cls(
            session_type=session_type,
            session_type_present=session_type_present,
            display_present=bool(environment.get("DISPLAY", "").strip()),
            wayland_display_present=bool(
                environment.get("WAYLAND_DISPLAY", "").strip()
            ),
            desktop_candidates=desktop_candidates,
        )


def detect_desktop_session(snapshot: EnvironmentSnapshot) -> DesktopSession:
    if not snapshot.session_type_present:
        return _unknown(SessionReasonCode.MISSING_SESSION_TYPE)
    if snapshot.session_type is None:
        return _unknown(SessionReasonCode.UNKNOWN_SESSION_TYPE)
    if snapshot.session_type is DisplayProtocol.XORG:
        if not snapshot.display_present:
            return _unknown(SessionReasonCode.MISSING_DISPLAY)
        if snapshot.wayland_display_present:
            return _unknown(SessionReasonCode.CONFLICTING_EVIDENCE)
    elif not snapshot.wayland_display_present:
        return _unknown(SessionReasonCode.MISSING_DISPLAY)

    desktop = DesktopEnvironment.UNKNOWN
    if len(snapshot.desktop_candidates) == 1:
        desktop = next(iter(snapshot.desktop_candidates))

    return DesktopSession(
        protocol=snapshot.session_type,
        desktop=desktop,
        confidence=1.0,
        reason_code=SessionReasonCode.DETECTED,
    )


def _unknown(reason_code: SessionReasonCode) -> DesktopSession:
    return DesktopSession(
        protocol=DisplayProtocol.UNKNOWN,
        desktop=DesktopEnvironment.UNKNOWN,
        confidence=0.0,
        reason_code=reason_code,
    )


def _normalize_session_type(value: str | None) -> DisplayProtocol | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"x11", "xorg"}:
        return DisplayProtocol.XORG
    if normalized == "wayland":
        return DisplayProtocol.WAYLAND
    return None


def _known_desktops(*values: str | None) -> frozenset[DesktopEnvironment]:
    candidates: set[DesktopEnvironment] = set()
    for value in values:
        if value is None:
            continue
        for token in _TOKEN_SEPARATOR.split(value.strip().lower()):
            desktop = _DESKTOP_ALIASES.get(token)
            if desktop is not None:
                candidates.add(desktop)
    return frozenset(candidates)
