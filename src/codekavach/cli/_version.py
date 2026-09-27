"""The installed version of CodeKavach, read from package metadata.

Owning epic: E05.
"""

import importlib.metadata

UNKNOWN_VERSION = "0.0.0+unknown"


def get_version() -> str:
    """The version from installed metadata, or ``0.0.0+unknown`` when not installed."""
    try:
        return importlib.metadata.version("codekavach")
    except importlib.metadata.PackageNotFoundError:
        return UNKNOWN_VERSION
