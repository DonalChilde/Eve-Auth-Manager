"""Shared CLI helpers for resolving settings and reading stdin input."""

import sys
from typing import cast

from typer import Context

from eve_auth_manager.settings import SETTINGS_KEY, EveAuthManagerSettings


def get_auth_manager_settings_from_context(ctx: Context) -> EveAuthManagerSettings:
    """Return EveAuthManagerSettings stored in the Typer context.

    Args:
        ctx: Typer command context whose obj mapping should contain the
            initialized Eve Auth Manager settings.

    Returns:
        EveAuthManagerSettings stored under the SETTINGS_KEY key.

    Raises:
        ValueError: If the context does not contain initialized Eve Auth
            Manager settings.
    """
    if ctx.obj is None or SETTINGS_KEY not in ctx.obj:
        raise ValueError(
            f"Auth Manager settings not found in context under key '{SETTINGS_KEY}'."
        )
    return cast(EveAuthManagerSettings, ctx.obj[SETTINGS_KEY])


def get_stdin() -> str:
    """Read piped or redirected stdin content until EOF.

    Returns:
        Full stdin content as a string.

    Raises:
        ValueError: If stdin is attached to an interactive terminal instead
            of a pipe or redirected input source.
    """
    if sys.stdin.isatty():
        raise ValueError("Error: provide a file path or pipe data via stdin.")
    return sys.stdin.read()
