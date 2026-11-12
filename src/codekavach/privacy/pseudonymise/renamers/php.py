"""The PHP renamer (E09-07).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers classes, traits, functions, methods, properties, constants and
variables. The ``$`` of a variable is outside the grammar's ``name`` node, so it is kept as
written; superglobals (``$_GET``) and the core function library stay in clear.
"""

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer


class PhpRenamer(BaseRenamer):
    """Renames the internal identifiers of a PHP file."""

    language = Language.PHP
