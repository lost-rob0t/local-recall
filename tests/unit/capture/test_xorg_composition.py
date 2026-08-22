from __future__ import annotations

from pathlib import Path

from local_recall.capture.composition import build_xorg_capture_backend


def test_build_xorg_capture_backend_composes_fixed_memory_only_stack() -> None:
    backend = build_xorg_capture_backend(
        xwd_executable=Path("/usr/bin/xwd"),
        xrandr_executable=Path("/usr/bin/xrandr"),
        environment={
            "DISPLAY": ":0",
            "XAUTHORITY": "/run/user/1000/Xauthority",
            "LD_PRELOAD": "/tmp/hostile.so",
        },
    )

    assert backend.backend_id == "xorg"


def test_build_xorg_capture_backend_rejects_relative_native_helpers() -> None:
    try:
        build_xorg_capture_backend(
            xwd_executable=Path("xwd"),
            xrandr_executable=Path("/usr/bin/xrandr"),
            environment={"DISPLAY": ":0"},
        )
    except ValueError as error:
        assert str(error) == "native executable path must be absolute"
    else:
        raise AssertionError("relative native helper was accepted")
