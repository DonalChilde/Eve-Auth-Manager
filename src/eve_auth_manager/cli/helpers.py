"""Helpers for the auth_manager CLI."""

import sys
from typing import cast

from typer import Context

from eve_auth_manager.settings import EveAuthManagerSettings


def get_auth_manager_settings_from_context(ctx: Context) -> EveAuthManagerSettings:
    """Helper function to get the auth_manager settings from the Typer context."""
    if ctx.obj is None or "eve-auth-manager-settings" not in ctx.obj:
        raise ValueError("Auth Manager settings not found in context.")
    return cast(EveAuthManagerSettings, ctx.obj["eve-auth-manager-settings"])


def get_stdin() -> str:
    """Read from stdin until EOF and return the content as a string."""
    if sys.stdin.isatty():
        raise ValueError("Error: provide a file path or pipe data via stdin.")
    return sys.stdin.read()
