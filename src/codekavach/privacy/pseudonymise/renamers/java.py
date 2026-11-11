"""The Java renamer (E09-06).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers packages' internal segments, classes, interfaces, enums, records and
their components, fields, methods, constructors (which carry the class name, so they agree with
it), parameters, locals, lambda parameters, type parameters and static imports. A field and a
local of the same name share a token, and ``this.total`` follows the field because it is the
same name. The language needs no node-by-node rule beyond that: the symbol table and the
classification decide what stays in clear (keywords, the class library, framework contract
names, annotation types), and a file that looks a member up by a string (``Class.forName``,
``getDeclaredField``) is left whole and counted, because the string names a binding that no
parse can follow.
"""

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer


class JavaRenamer(BaseRenamer):
    """Renames the internal identifiers of a Java file."""

    language = Language.JAVA
