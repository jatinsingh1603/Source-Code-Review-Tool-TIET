"""The built-in matchers, registered in one place.

Owning epic: E13. MVP; extended by E16, whose pack loader registers rule-language generators in the
same registry.
"""

from typing import Final

from codekavach.analysis.rules.base import GeneratorRegistry
from codekavach.analysis.rules.engine import NodeMatcher
from codekavach.analysis.rules.matchers.command_injection import CommandInjectionMatcher
from codekavach.analysis.rules.matchers.deserialisation import DeserialisationMatcher
from codekavach.analysis.rules.matchers.direct_object_reference import DirectObjectReferenceMatcher
from codekavach.analysis.rules.matchers.missing_authorization import MissingAuthorizationMatcher
from codekavach.analysis.rules.matchers.path_traversal import PathTraversalMatcher
from codekavach.analysis.rules.matchers.sql_injection import SqlInjectionMatcher
from codekavach.analysis.rules.matchers.ssrf import SsrfMatcher
from codekavach.analysis.rules.matchers.weak_crypto import WeakCryptoMatcher
from codekavach.analysis.rules.matchers.xss import XssMatcher

BUILTIN_MATCHERS: Final[tuple[NodeMatcher, ...]] = (
    SqlInjectionMatcher(),
    CommandInjectionMatcher(),
    PathTraversalMatcher(),
    SsrfMatcher(),
    DeserialisationMatcher(),
    WeakCryptoMatcher(),
    MissingAuthorizationMatcher(),
    DirectObjectReferenceMatcher(),
    XssMatcher(),
)


def default_registry() -> GeneratorRegistry:
    """A fresh registry holding every built-in matcher."""
    return GeneratorRegistry(BUILTIN_MATCHERS)
