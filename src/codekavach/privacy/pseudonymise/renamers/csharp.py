"""The C# renamer (E09-07).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers namespaces' internal segments, types, members, properties, locals,
parameters, lambda parameters and enum members. The base class library, ASP.NET and EF Core
surface and framework contract names stay in clear.
"""

from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer


class CSharpRenamer(BaseRenamer):
    """Renames the internal identifiers of a C# file."""

    language = Language.CSHARP
