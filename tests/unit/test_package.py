import json
import sys

import pytest
from typer.testing import CliRunner

from local_recall import __version__
from local_recall.cli import app


def test_runtime_targets_python_314() -> None:
    assert sys.version_info[:2] == (3, 14)


def test_version_is_defined() -> None:
    assert __version__ == "0.1.0.dev0"


def test_version_command() -> None:
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_status_reports_selected_strategies_without_environment_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "secret-display-marker"
    monkeypatch.setenv("XDG_SESSION_TYPE", "x11")
    monkeypatch.setenv("DISPLAY", marker)
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "Qtile")
    monkeypatch.setenv("UNRELATED_SECRET", marker)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    result = CliRunner().invoke(app, ["status"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["protocol"] == "xorg"
    assert payload["desktop"] == "qtile"
    assert payload["capture_backend"] == "xorg-generic"
    assert payload["metadata_sources"] == ["xorg-generic"]
    assert payload["recording_supported"] is True
    assert marker not in result.stdout


def test_status_fails_closed_for_wayland(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = "wayland-sensitive-path"
    monkeypatch.setenv("XDG_SESSION_TYPE", "wayland")
    monkeypatch.setenv("WAYLAND_DISPLAY", marker)
    monkeypatch.delenv("DISPLAY", raising=False)

    result = CliRunner().invoke(app, ["status"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["protocol"] == "wayland"
    assert payload["capture_backend"] is None
    assert payload["metadata_sources"] == []
    assert payload["recording_supported"] is False
    assert marker not in result.stdout
