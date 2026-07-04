import typer

from eve_auth_manager.cli.credentials.add import app as add_app
from eve_auth_manager.cli.credentials.display import app as display_app
from eve_auth_manager.cli.credentials.remove import app as remove_app

app = typer.Typer(
    no_args_is_help=True,
    name="credentials",
    help="Manage ESI authentication credentials.",
)

app.add_typer(add_app)
app.add_typer(display_app)
app.add_typer(remove_app)
