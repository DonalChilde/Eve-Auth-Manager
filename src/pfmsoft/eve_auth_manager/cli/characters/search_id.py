"""Command to search EVE Online entity IDs by name."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from pfmsoft.eve_auth_manager.helpers.http_session_factory import client_manager
from pfmsoft.eve_auth_manager.helpers.save_text_file import save_text_file

app = typer.Typer(no_args_is_help=True, help="Search EVE Online entity IDs by name.")

SEARCH_ENDPOINT = "https://esi.evetech.net/universe/ids"
"""ESI universe IDs lookup endpoint."""


@app.command(name="search")
def search(
    search_strings: Annotated[
        list[str],
        typer.Option(
            "--name",
            help="Exact entity name to search. Repeat for multiple names.",
        ),
    ],
    file_path: Annotated[
        Path,
        typer.Option(
            "--to",
            help="Output path for JSON results. Use '-' to write to stdout.",
            dir_okay=False,
            writable=True,
            allow_dash=True,
        ),
    ] = Path("-"),
    plain: Annotated[
        bool,
        typer.Option(
            "--plain",
            help="When writing to stdout, emit plain JSON text instead of Rich output.",
        ),
    ] = False,
    indent: Annotated[
        int | None,
        typer.Option(
            "--indent",
            help="Number of spaces to use for indentation in the plain or file output "
            "JSON. Defaults to None.",
        ),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            help="Overwrite the output file if it already exists.",
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
    """Search EVE Online entity IDs by exact names.

    Queries the ESI universe IDs endpoint and returns JSON grouped by entity
    type.

    Example:
        uv run eve-auth characters search --search Tritanium

    Output shape:
        {
            "characters": [{"id": 243070982, "name": "Tritanium"}],
            "inventory_types": [{"id": 34, "name": "Tritanium"}]
        }

    Notes:
        1. Matching is exact but case-insensitive, as defined by ESI.
        2. Result keys vary based on matching entity types.
    """
    if quiet:
        messenger = Console(stderr=True, quiet=True)
    else:
        messenger = Console(stderr=True)
    assert isinstance(search_strings, list) and all(
        isinstance(s, str) for s in search_strings
    ), "search_strings must be a list of strings"
    messenger.print(f"Searching for the following names: {', '.join(search_strings)}")
    with client_manager() as session:
        # Send a POST request to the ESI search endpoint with the search strings as JSON
        response = session.post(url=SEARCH_ENDPOINT, json=search_strings)
        response.raise_for_status()
        search_results = response.json()
        if not search_results:
            messenger.print("[yellow]No results found.[/yellow]")
            raise typer.Exit(0)
        if file_path == Path("-"):
            if plain:
                print(json.dumps(search_results, indent=indent))
            else:
                messenger.print(search_results)
        else:
            output_path = save_text_file(
                text=json.dumps(search_results, indent=indent),
                output_directory=file_path.parent,
                file_name=file_path.name,
                overwrite=overwrite,
            )
            messenger.print(f"Output written to {output_path}")
