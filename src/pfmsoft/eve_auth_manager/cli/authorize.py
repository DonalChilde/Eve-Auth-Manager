"""CLI command for refreshing an authorized character and emitting an AuthorizedDict."""

from pathlib import Path
from typing import Annotated, NotRequired, TypedDict
from uuid import UUID

import typer
from pydantic import RootModel
from rich.console import Console

from pfmsoft.eve_auth_manager.cli.helpers import (
    get_auth_manager_settings_from_context,
    get_stdin,
)
from pfmsoft.eve_auth_manager.helpers.save_text_file import save_text_file
from pfmsoft.eve_auth_manager.models import AuthorizedDict, AuthorizedDictRoot
from pfmsoft.eve_auth_manager.sqlite.manager import SqliteAuthManager

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
            help="Path to a JSON object with authorize arguments. Use '-' to read JSON from stdin.",
            dir_okay=False,
            readable=True,
            allow_dash=True,
        ),
    ] = None,
    file_out: Annotated[
        Path,
        typer.Option(
            "--to",
            help="Output path for AuthorizedDict JSON. Use '-' to write to stdout.",
            dir_okay=False,
            writable=True,
            allow_dash=True,
        ),
    ] = Path("-"),
    cred_id: Annotated[
        UUID | None,
        typer.Option(
            "--cred-id",
            help="Credential ID to use. One of --cred-id or --cred-name is required."
            " Takes precedence over --cred-name.",
        ),
    ] = None,
    cred_name: Annotated[
        str | None,
        typer.Option(
            "--cred-name",
            help="Credential name to use when --cred-id is not provided.",
        ),
    ] = None,
    character_id: Annotated[
        int | None,
        typer.Option("--character-id", help="ID of the character to authorize"),
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
    """Refresh an authorized character and output an AuthorizedDict JSON payload.

    Combines arguments from CLI options and an optional JSON input source,
    refreshes the selected character if needed, and emits the
    authorization payload.

    Input:
        Arguments may be provided by CLI options and optionally by --from JSON.
        The --from JSON object supports these fields:

        cred_id: Credential UUID to use for authorization.
        cred_name: Credential name to use when cred_id is not provided.
        character_id: Character ID to authorize.
        min_seconds: Minimum token lifetime required before refresh.

    Notes:
        1. At least one of --cred-id or --cred-name must be provided.
        2. CLI option values take precedence over values loaded from JSON
           input.
        3. Validation is performed after combining the JSON and CLI argument
           sources.
        4. If both --cred-id and --cred-name are provided, --cred-id takes
           precedence.

    Output:
        Emits an AuthorizedDict JSON object. The payload is written to stdout
        when --to - is used, otherwise it is written to the requested file.

        AuthorizedDict fields:
            cred_id: String form of the credential UUID used for the
                authorization.
            character_id: Numeric EVE character ID associated with the access
                token.
            character_name: Human-readable EVE character name associated with
                the access token.
            access_token: Bearer token value that can be used for authorized
                ESI requests.
            expires_at: Unix epoch timestamp, in seconds, when the access
                token expires.
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
            "Either --cred-id or --cred-name must be provided.", param_hint="cred-id"
        )
    settings = get_auth_manager_settings_from_context(ctx)
    with SqliteAuthManager(settings.authorization_database_path) as auth_manager:
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
