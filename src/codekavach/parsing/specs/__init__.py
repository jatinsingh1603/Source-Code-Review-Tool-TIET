"""The built-in language specs: Python, JavaScript, TypeScript, Java and Go (E07-02, E07-05).

Owning epic: E07. Importing this package registers every spec it ships: each submodule calls
``SpecRegistry.register`` at the bottom of its own file, as an import side effect, so the
imports below exist to run that code and are never referenced by name afterwards. Written as
``import x.y as y``, not ``from x import y``: the latter's AST node does not visibly name the
submodule, which the layout test (``tests/unit/test_package_layout.py``) checks for.
"""

import codekavach.parsing.specs.go as go  # noqa: F401, PLR0402 - see above
import codekavach.parsing.specs.java as java  # noqa: F401, PLR0402 - see above
import codekavach.parsing.specs.javascript as javascript  # noqa: F401, PLR0402 - see above
import codekavach.parsing.specs.python as python  # noqa: F401, PLR0402 - see above

__all__: list[str] = []
