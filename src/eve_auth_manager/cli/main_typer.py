"""Standalone Typer entry point for Eve Auth Manager.

Initializes application settings and logging when the packaged CLI is run
directly.

Notes:
    This module is only used for the standalone CLI entry point. When the
    commands are embedded in another Typer application, that application is
    responsible for initializing EveAuthManagerSettings and storing them in
    typer.Context.obj under the eve-auth-manager-settings key.
"""

import logging
from dataclasses import asdict

import typer

from eve_auth_manager import __app_name__, __version__
from eve_auth_manager.cli.authorize import app as authorize_app
from eve_auth_manager.cli.characters import app as characters_app
from eve_auth_manager.cli.credentials import app as credentials_app
from eve_auth_manager.cli.util import app as util_app
from eve_auth_manager.cli.version import app as version_app
from eve_auth_manager.logging_config import setup_logging
from eve_auth_manager.settings import get_settings

logger = logging.getLogger(__name__)


def default_options(ctx: typer.Context) -> None:
    """Initialize settings and logging for standalone CLI execution.

    Args:
        ctx: Typer command context used to store shared application settings
            for downstream subcommands.

    Notes:
        The resolved EveAuthManagerSettings object is stored in ctx.obj under
        the eve-auth-manager-settings key.
    """
    settings = get_settings()
    setup_logging(log_dir=settings.logging_directory)
    ctx.obj = {"eve-auth-manager-settings": settings}
    logger.info(
        f"Starting {__app_name__} v{__version__} with settings: {asdict(settings)!r}"
    )


app = typer.Typer(
    no_args_is_help=True,
    callback=default_options,
    help="Manage ESI authentication credentials and tokens.",
)
app.add_typer(authorize_app)
app.add_typer(credentials_app)
app.add_typer(characters_app)
app.add_typer(util_app)
app.add_typer(version_app)
