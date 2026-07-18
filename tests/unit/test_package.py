import sys

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
