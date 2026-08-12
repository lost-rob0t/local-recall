"""Command-line entry point for the Local Recall scaffold."""

import asyncio
import os

import typer

from local_recall import __version__
from local_recall.metadata import GenericXorgMetadataSource, QtileMetadataSource
from local_recall.session import (
    EnvironmentSnapshot,
    GenericXorgMetadataProbe,
    QtileMetadataProbe,
    SessionResolver,
    render_session_resolution_status,
)

app = typer.Typer(
    name="local-recall",
    help="Local-first encrypted desktop activity recall.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Local Recall command group."""


@app.command()
def version() -> None:
    """Print the installed Local Recall version."""
    typer.echo(__version__)


@app.command()
def status() -> None:
    """Print the sanitized desktop-session strategy status."""
    qtile_source = QtileMetadataSource()
    qtile_probe = QtileMetadataProbe(qtile_source)
    generic_xorg_source = GenericXorgMetadataSource()
    generic_xorg_probe = GenericXorgMetadataProbe(generic_xorg_source.is_available)
    resolver = SessionResolver((qtile_probe,), generic_xorg_probe=generic_xorg_probe)
    resolution = asyncio.run(
        resolver.resolve(
            EnvironmentSnapshot.from_mapping(os.environ),
            (qtile_probe.source_id, generic_xorg_probe.source_id),
        )
    )
    typer.echo(render_session_resolution_status(resolution))
