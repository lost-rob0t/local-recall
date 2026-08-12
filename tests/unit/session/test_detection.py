from local_recall.session import (
    DesktopEnvironment,
    DisplayProtocol,
    EnvironmentSnapshot,
    SessionReasonCode,
    detect_desktop_session,
)


def test_detects_qtile_xorg_from_mocked_environment() -> None:
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
            "XDG_CURRENT_DESKTOP": "Qtile",
        }
    )

    session = detect_desktop_session(snapshot)

    assert session.protocol is DisplayProtocol.XORG
    assert session.desktop is DesktopEnvironment.QTILE
    assert session.reason_code is SessionReasonCode.DETECTED
    assert session.confidence == 1.0


def test_detects_wayland_without_misclassifying_xwayland_display() -> None:
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "wayland",
            "WAYLAND_DISPLAY": "wayland-1",
            "DISPLAY": ":1",
            "XDG_CURRENT_DESKTOP": "sway",
        }
    )

    session = detect_desktop_session(snapshot)

    assert session.protocol is DisplayProtocol.WAYLAND
    assert session.desktop is DesktopEnvironment.SWAY
    assert session.reason_code is SessionReasonCode.DETECTED


def test_missing_session_type_does_not_guess_from_display() -> None:
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "DISPLAY": ":0",
            "XDG_CURRENT_DESKTOP": "Qtile",
        }
    )

    session = detect_desktop_session(snapshot)

    assert session.protocol is DisplayProtocol.UNKNOWN
    assert session.reason_code is SessionReasonCode.MISSING_SESSION_TYPE
    assert session.confidence == 0.0


def test_xorg_hint_without_display_fails_closed() -> None:
    snapshot = EnvironmentSnapshot.from_mapping({"XDG_SESSION_TYPE": "x11"})

    session = detect_desktop_session(snapshot)

    assert session.protocol is DisplayProtocol.UNKNOWN
    assert session.reason_code is SessionReasonCode.MISSING_DISPLAY


def test_unknown_session_type_fails_closed() -> None:
    snapshot = EnvironmentSnapshot.from_mapping(
        {"XDG_SESSION_TYPE": "synthetic-protocol", "DISPLAY": ":0"}
    )

    session = detect_desktop_session(snapshot)

    assert session.protocol is DisplayProtocol.UNKNOWN
    assert session.reason_code is SessionReasonCode.UNKNOWN_SESSION_TYPE


def test_conflicting_recognized_desktops_are_not_guessed() -> None:
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
            "XDG_CURRENT_DESKTOP": "Qtile",
            "DESKTOP_SESSION": "GNOME",
        }
    )

    session = detect_desktop_session(snapshot)

    assert session.protocol is DisplayProtocol.XORG
    assert session.desktop is DesktopEnvironment.UNKNOWN


def test_conflicting_xorg_evidence_fails_closed() -> None:
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
            "WAYLAND_DISPLAY": "wayland-1",
        }
    )

    session = detect_desktop_session(snapshot)

    assert session.protocol is DisplayProtocol.UNKNOWN
    assert session.reason_code is SessionReasonCode.CONFLICTING_EVIDENCE


def test_unknown_desktop_values_are_not_retained() -> None:
    marker = "synthetic-user-session-value"
    snapshot = EnvironmentSnapshot.from_mapping(
        {
            "XDG_SESSION_TYPE": "x11",
            "DISPLAY": ":0",
            "XDG_CURRENT_DESKTOP": marker,
        }
    )

    session = detect_desktop_session(snapshot)

    assert session.desktop is DesktopEnvironment.UNKNOWN
    assert marker not in repr(snapshot)
    assert marker not in repr(session)
