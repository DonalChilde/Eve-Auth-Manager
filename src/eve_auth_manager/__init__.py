"""The Authentication Manager module."""

from importlib.metadata import version

__project_namespace__ = "pfmsoft"
__author__ = "Chad Lowe"
__email__ = "pfmsoft.dev@gmail.com"
__app_name__ = "pfmsoft-eve-auth-manager"  # Must match the name in pyproject.toml, used in determining the app_dir and other paths.
__version__ = version(__app_name__)
__description__ = "CLI and API helpers for acquiring, storing, and refreshing EVE Online ESI OAuth tokens"
__release__ = __version__
__url__ = "https://github.com/DonalChilde/pfmsoft-eve-auth-manager"
__license__ = "MIT"
