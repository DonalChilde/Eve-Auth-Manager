"""Command to output an AuthorizedDict."""

from pathlib import Path
from typing import Annotated, NotRequired, TypedDict
from uuid import UUID

import typer
from pydantic import RootModel
from rich.console import Console

from eve_auth_manager.cli.helpers import (
    get_auth_manager_settings_from_context,
    get_stdin,
)
from eve_auth_manager.helpers.save_text_file import save_text_file
from eve_auth_manager.models import AuthorizedDict, AuthorizedDictRoot
from eve_auth_manager.sqlite.manager import SqliteAuthManager

app = typer.Typer(no_args_is_help=True)


class _ParsedArgs(TypedDict):
    cred_id: NotRequired[UUID]
    cred_name: NotRequired[str]
    character_id: NotRequired[int]
    min_seconds: NotRequired[int]


class _CliArgs(TypedDict):
    cred_id: UUID | None
    cred_name: str | None
    character_id: int | None
    min_seconds: int | None


class _Arguments(TypedDict):
    cred_id: UUID | None
    cred_name: str | None
    character_id: int
    min_seconds: int


ParsedArgsRoot = RootModel[_ParsedArgs]
ArgumentsRoot = RootModel[_Arguments]


@app.command(name="authorize")
def authorize(
    ctx: typer.Context,
    json_args: Annotated[
        Path | None,
        typer.Option(
            "--from",
            help="Path to a file containing a JSON string of the arguments to pass to the "
            "authorize_character method. If `-` is provided, the JSON string will be read from stdin.",
            dir_okay=False,
            readable=True,
            allow_dash=True,
        ),
    ] = None,
    file_out: Annotated[
        Path,
        typer.Option(
            "--to",
            help="Path to a file to write the AuthorizedDict JSON. Defaults to stdout.",
            dir_okay=False,
            writable=True,
            allow_dash=True,
        ),
    ] = Path("-"),
    cred_id: Annotated[
        UUID | None,
        typer.Option(
            "--cred_id", help="ID of the credentials to use for authorization"
        ),
    ] = None,
    cred_name: Annotated[
        str | None,
        typer.Option(
            "--cred_name", help="Name of the credentials to use for authorization"
        ),
    ] = None,
    character_id: Annotated[
        int | None,
        typer.Option("--character_id", help="ID of the character to authorize"),
    ] = None,
    min_seconds: Annotated[
        int,
        typer.Option(
            "--min-seconds",
            help="Minimum number of seconds remaining on the access token before it will "
            "be refreshed.",
        ),
    ] = 300,
    indent: Annotated[
        int | None,
        typer.Option(
            "--indent",
            help="Number of spaces to use for indentation in the output JSON. Defaults to None.",
        ),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Overwrite the existing AuthorizedDict file if it exists.",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress output messages.",
        ),
    ] = False,
) -> None:
    """Refresh a character and output an AuthorizedDict.

    This command can get arguments from:
    1. Command line arguments
    2. A JSON file specified with the `--from` option
    3. A JSON string read from stdin if `--from -` is specified

    Command line arguments take precedence over JSON file or stdin arguments.
    If both `--cred_id` and `--cred_name` are provided, `--cred_id` takes precedence.
    A complete set of arguments must be provided from the various sources.

    The json_args file or stdin can contain any of the following fields:
    - cred_id: The ID of the credentials to use for authorization.
    - cred_name: The name of the credentials to use for authorization.
    - character_id: The ID of the character to authorize.
    - min_seconds: The minimum number of seconds remaining on the access token before it will be refreshed.

    Outputs a json dictionary containing the following fields:
    - cred_id: The ID of the credentials used for authorization.
    - character_id: The ID of the character that was authorized.
    - character_name: The name of the character that was authorized.
    - access_token: The access token for the character.
    - expires_at: The timestamp of when the access token will expire, in seconds since the epoch.
    """
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)

    parsed_arguments: _ParsedArgs = {}
    # If json_args is provided, parse it and combine it with the CLI args, with CLI args taking precedence.
    if json_args is not None:
        if json_args == Path("-"):
            parsed_arguments = ParsedArgsRoot.model_validate_json(
                get_stdin(), extra="ignore"
            ).root
        else:
            parsed_arguments = ParsedArgsRoot.model_validate_json(
                json_args.read_text(), extra="ignore"
            ).root
    cli_args: _CliArgs = {
        "cred_id": cred_id,
        "cred_name": cred_name,
        "character_id": character_id,
        "min_seconds": min_seconds,
    }
    # combine the CLI args with the JSON args, with CLI args taking precedence
    combined: _Arguments = parsed_arguments | cli_args  # type: ignore
    # Validate the combined arguments and ensure all required fields are present
    arguments = ArgumentsRoot.model_validate(combined).root
    if arguments["cred_id"] is None and arguments["cred_name"] is None:
        raise typer.BadParameter(
            "Either --cred_id or --cred_name must be provided.", param_hint="cred_id"
        )
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.auth_db_path) as auth_manager:
        credential = auth_manager.get_credential(
            cred_id=arguments["cred_id"], cred_name=arguments["cred_name"]
        )
        character = auth_manager.refresh_character(
            cred_id=credential.cred_id,
            character_id=arguments["character_id"],
            min_seconds=arguments["min_seconds"],
        )
    authorized_dict = AuthorizedDict(
        cred_id=str(character.cred_id),
        character_id=character.character_id,
        character_name=character.character_name,
        access_token=character.oauth_token.access_token,
        expires_at=character.expires_at,
    )
    authorized_root = AuthorizedDictRoot.model_validate(authorized_dict)
    if file_out == Path("-"):
        # stdout.print(authorized_root.model_dump_json(), highlight=False)
        print(authorized_root.model_dump_json(indent=indent))
    else:
        out_path = save_text_file(
            text=authorized_root.model_dump_json(indent=indent),
            output_directory=file_out.parent,
            file_name=file_out.name,
            overwrite=overwrite,
        )
        messenger.print(f"AuthorizedDict saved to {out_path}")
