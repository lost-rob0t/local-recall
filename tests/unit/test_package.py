import sys
from pathlib import Path

import pykka
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


def test_bootstrap_installs_console_entry_point() -> None:
    entry_point = Path(sys.executable).with_name("local-recall")

    assert entry_point.is_file()
    assert entry_point.stat().st_mode & 0o111


def test_status_fails_closed_when_daemon_transport_is_unavailable() -> None:
    result = CliRunner().invoke(app, ["status"])

    assert result.exit_code == 3
    assert result.stdout.strip() == "daemon-unavailable"


def test_status_does_not_start_local_lifecycle_actors() -> None:
    before = tuple(pykka.ActorRegistry.get_all())

    result = CliRunner().invoke(app, ["status"])

    assert result.exit_code == 3
    assert tuple(pykka.ActorRegistry.get_all()) == before
