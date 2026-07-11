import typer

from .authorize import app as authorize_app
from .characters import app as characters_app
from .credentials import app as credentials_app
from .util import app as util_app
from .version import app as version_app

app = typer.Typer(no_args_is_help=True, help="EVE Auth Manager CLI")

app.add_typer(
    authorize_app, name="authorize", help="Get an AuthorizeDict for a character."
)
app.add_typer(characters_app, name="characters", help="Manage EVE characters")
app.add_typer(credentials_app, name="credentials", help="Manage EVE credentials")
app.add_typer(util_app, name="util", help="Utility commands")
app.add_typer(version_app, name="version", help="Show version information")
