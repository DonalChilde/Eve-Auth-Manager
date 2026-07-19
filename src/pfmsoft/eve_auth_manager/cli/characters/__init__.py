import typer

from pfmsoft.eve_auth_manager.cli.characters.add import app as add_app
from pfmsoft.eve_auth_manager.cli.characters.display import app as display_app
from pfmsoft.eve_auth_manager.cli.characters.refresh import app as refresh_app
from pfmsoft.eve_auth_manager.cli.characters.revoke import app as revoke_app
from pfmsoft.eve_auth_manager.cli.characters.search_id import app as search_id_app

app = typer.Typer(
    no_args_is_help=True,
    name="characters",
    help="Manage authorized character tokens.",
)

app.add_typer(add_app)
app.add_typer(display_app)
app.add_typer(refresh_app)
app.add_typer(revoke_app)
app.add_typer(search_id_app)
