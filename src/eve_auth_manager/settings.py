"""Configuration models and OAuth-related constants for Eve Auth Manager."""

from dataclasses import dataclass
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from typer import get_app_dir

from eve_auth_manager import __app_name__, __url__, __version__

AUDIENCE = "EVE Online"
"""Expected JWT audience for EVE SSO access tokens."""
USER_AGENT = f"{__app_name__} ({__version__}) (+{__url__}) auth_manager stand alone"
"""User-Agent header value sent to remote OAuth and ESI services."""
OAUTH_METADATA_URL = (
    "https://login.eveonline.com/.well-known/oauth-authorization-server"
)
"""URL to fetch OAuth metadata from the ESI auth server."""


@dataclass(slots=True, kw_only=True)
class EveAuthManagerSettings:
    """Normalized runtime settings used by the application.

    This lightweight dataclass provides the settings shape consumed by the
    rest of the codebase without exposing the Pydantic settings dependency
    directly.
    """

    application_directory: Path
    authorization_database_path: Path
    logging_directory: Path


class EveAuthManagerSettingsPydantic(BaseSettings):
    """Environment-backed settings loader for Eve Auth Manager.

    Loads configuration from environment variables prefixed with
    EVE_AUTH_MANAGER_ and supplies default filesystem locations when values
    are not provided.
    """

    model_config = SettingsConfigDict(
        env_prefix="EVE_AUTH_MANAGER_",
        env_file=".env",
        env_file_encoding="utf-8",
    )
    application_directory: Path = Path(get_app_dir(__app_name__))


def get_settings(
    pydantic_settings: EveAuthManagerSettingsPydantic | None = None,
) -> EveAuthManagerSettings:
    """Build the normalized application settings object.

    Args:
        pydantic_settings: Optional preconfigured environment-backed settings
            instance. If omitted, a default instance is created.

    Returns:
        EveAuthManagerSettings with resolved database and logging paths.

    Notes:
        1. If the CLI is run directly, the settings are initialized in the
           Typer app callback and stored in typer context.obj.
        2. If the CLI is imported into another CLI, that CLI initializes the
           EveAuthManagerSettings object either directly or through an
           EveAuthManagerSettingsPydantic instance, then stores the result in
           typer context.obj.
        3. If this code is imported into another package, that package is
           responsible for creating the EveAuthManagerSettings object.
    """
    pydantic_settings = pydantic_settings or EveAuthManagerSettingsPydantic()
    return EveAuthManagerSettings(
        application_directory=pydantic_settings.application_directory,
        authorization_database_path=pydantic_settings.application_directory
        / "eve_auth_manager.sqlite",
        logging_directory=pydantic_settings.application_directory / "logs",
    )
