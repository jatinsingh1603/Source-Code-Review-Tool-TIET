"""The Kotlin renamer (E09-07).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers classes, objects, functions, properties, parameters, enum
entries, locals and lambda parameters. The symbol table and the classification decide what stays
in clear (keywords, the standard and JVM class library, framework contract names); a string
that names a member by reflection is left whole and counted.
"""

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer


class KotlinRenamer(BaseRenamer):
    """Renames the internal identifiers of a Kotlin file."""

    language = Language.KOTLIN
