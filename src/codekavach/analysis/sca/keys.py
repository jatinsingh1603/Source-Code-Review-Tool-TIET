"""Artefact keys of the SCA stage (E19-01).

``dependencies`` holds the ``DependencyGraph`` and ``sbom`` the CycloneDX document. Both describe
the client's architecture, so they are raw-data keys: no LLM-category stage may declare them in
its requirements (``tests/unit/analysis/sca/test_keys.py`` asserts it).
"""

from typing import Final

from codekavach.core.pipeline.keys import is_valid_key

DEPENDENCIES: Final = "dependencies"
SBOM: Final = "sbom"
SCA_KEYS: Final = frozenset({DEPENDENCIES, SBOM})

if not all(is_valid_key(key) for key in SCA_KEYS):  # import-time vocabulary check
    raise ValueError("SCA artefact keys must satisfy the shared key predicate")
