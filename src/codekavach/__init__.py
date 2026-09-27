"""CodeKavach: privacy-preserving, LLM-assisted secure source code review."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("codekavach")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
