"""The C++ renamer (E09-07).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers namespaces, classes, templates, methods, fields, locals, parameters and
lambdas. ``std`` and the C and C++ library surface stay in clear; a qualified name's segments are
renamed one by one. Macro bodies are handled as in the C renamer.
"""

from codekavach.core.models import Language
from codekavach.parsing.specs.c_family import CPP_BUILTINS, CPP_KEYWORDS
from codekavach.privacy.pseudonymise.renamers.c import CRenamer


class CppRenamer(CRenamer):
    """Renames the internal identifiers of a C++ file."""

    language = Language.CPP
    keep = CPP_KEYWORDS | CPP_BUILTINS
