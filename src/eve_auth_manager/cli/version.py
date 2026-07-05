"""Version command for the Eve Auth Manager CLI."""

import typer

from eve_auth_manager import __app_name__, __url__, __version__

app = typer.Typer(no_args_is_help=True)


@app.command(
    name="version",
    help="Show the installed CLI version and project URL.",
)
def version() -> None:
    """Display build and project metadata for the current CLI install."""
    typer.echo(f"{__app_name__} version {__version__}")
    typer.echo(f"Project URL: {__url__}")
