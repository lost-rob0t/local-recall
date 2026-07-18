"""Command-line entry point for the Local Recall scaffold."""

import typer

from local_recall import __version__

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
