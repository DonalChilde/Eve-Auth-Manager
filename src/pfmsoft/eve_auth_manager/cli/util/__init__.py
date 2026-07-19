"""Commands for database maintenance tasks."""

import typer

from pfmsoft.eve_auth_manager.cli.util.reset import app as reset_app

app = typer.Typer(
    no_args_is_help=True, name="util", help="Database maintenance commands."
)
app.add_typer(reset_app)
