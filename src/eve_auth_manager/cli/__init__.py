"""EVE Auth Manager CLI.

These commands are intended to also be available when the CLI is embedded in another
Typer application.
"""

import typer

from .characters import app as characters_app
from .credentials import app as credentials_app
from .util import app as util_app

app = typer.Typer(no_args_is_help=True, help="EVE Auth Manager CLI")


app.add_typer(characters_app, name="characters", help="Manage EVE characters")
app.add_typer(credentials_app, name="credentials", help="Manage EVE credentials")
app.add_typer(util_app, name="util", help="Utility commands")
