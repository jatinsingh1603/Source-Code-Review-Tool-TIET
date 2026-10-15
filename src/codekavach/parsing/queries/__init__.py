"""Tree-sitter query files, loaded with importlib.resources.

Owning epic: E07. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.parsing.queries.loader import (
    QueryError,
    QueryNotFoundError,
    load_combined_query,
    load_query,
)

__all__ = ["QueryError", "QueryNotFoundError", "load_combined_query", "load_query"]
