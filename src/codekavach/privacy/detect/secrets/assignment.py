"""The ``secret.assignment`` detector: a credential-named identifier assigned a string literal.

Owning epic: E08.

An identifier whose sub-words (``split_subtokens``, E07-03) include a credential word and which is
assigned a string literal is reported as ``generic_credential``: ``LOW``, or ``MEDIUM`` when the
literal is at least 12 characters and not a known placeholder. The head word decides: a name that
ends in ``hint``, ``prompt``, ``label``, ``url`` and the like names something *about* a
credential, so ``passwordHint`` does not fire and ``api_key`` and ``authToken`` do. ``max_tokens``
does not fire either: ``tokens`` is not ``token``.

Two entry points, one rule:

* :meth:`AssignmentDetector.detect` is a line-based pass. It needs no parse, so it works on
  ``.env`` files, YAML, INI, TOML and JSON as well as code. In code a value must be quoted; in a
  configuration file (by language or file name) a bare value counts too.
* :meth:`AssignmentDetector.detect_parsed` walks the parse tree of a ``ParsedFile`` and takes the
  name from the node the literal is assigned to, so it sees the exact literal in any grammar,
  including multi-line strings and concatenations the line pass cannot.

Values that are references and not literals (``${DB_PASSWORD}``, ``{{ vault }}``,
``%(name)s``) are skipped. This module performs no network operation.
"""

import re
from collections.abc import Iterable, Iterator
from functools import lru_cache
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Any, Final

from codekavach.core.models import Confidence, Language, PlaceholderKind, RawCode, RepoPath
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.subtokens import split_subtokens
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.detect.offsets import ByteOffsets
from codekavach.privacy.detect.safe_regex import safe_compile
from codekavach.privacy.detect.secrets.filters import is_placeholder

DETECTOR_ID: Final = "secret.assignment"
SUBTYPE: Final = "generic_credential"
MEDIUM_MIN_LENGTH: Final = 12
MIN_VALUE_LENGTH: Final = 4
_MAX_VALUE: Final = 512

CREDENTIAL_WORDS: Final = frozenset(
    {"password", "passwd", "pwd", "secret", "token", "apikey", "credential", "auth"}
)
CREDENTIAL_PAIRS: Final = frozenset(
    {"api_key", "access_key", "private_key", "session_key", "signing_key"}
)
NON_SECRET_HEADS: Final = frozenset(
    {
        "hint", "prompt", "label", "placeholder", "text", "message", "msg", "name", "length",
        "policy", "type", "url", "uri", "path", "file", "field", "regex", "pattern", "header",
        "endpoint", "expiry", "expires", "ttl", "id",
    }
)  # fmt: skip
CONFIG_LANGUAGES: Final = frozenset({Language.YAML, Language.TOML})
CONFIG_SUFFIXES: Final = frozenset({".env", ".ini", ".cfg", ".conf", ".properties", ".toml"})
_KEYWORDS_NOT_STRINGS: Final = frozenset(
    {"true", "false", "null", "none", "nil", "undefined", "yes", "no", "on", "off"}
)
_REFERENCE_START: Final = frozenset("$%<!&*|>@{[(")

_SIZE = f"{{{MIN_VALUE_LENGTH},{_MAX_VALUE}}}"
_QUOTED_VALUE = rf"""(?:"(?:[^"\\\r\n]|\\.){_SIZE}"|'(?:[^'\\\r\n]|\\.){_SIZE}')"""
_NAME = r"""(?P<name>["']?[A-Za-z_][\w.\-]{0,63}["']?)"""
_SEPARATOR = r"""[ \t]*(?::=|=>|=(?!=)|:(?!:))[ \t]*"""
# A name starts at the beginning of a word: without the look-behind every position inside a
# long identifier started a failed attempt.
_ASSIGNMENT: Final = safe_compile(
    r"(?<![\w.\-])" + _NAME + _SEPARATOR + rf"(?P<quoted>{_QUOTED_VALUE})"
)
_BARE_ASSIGNMENT: Final = safe_compile(
    r"""(?m)^[ \t-]*(?:export[ \t]+)?"""
    + _NAME
    + _SEPARATOR
    + rf"""(?P<bare>[^\s"'#,;]{_SIZE})[ \t]*\r?$"""
)
_LITERAL_PARTS: Final = safe_compile(
    r"""(?s)(?P<prefix>[A-Za-z]{0,2})(?P<quote>'''|\"\"\"|'|"|`)(?P<body>.*)(?P=quote)"""
)
_STRING_NODE_TYPES: Final = frozenset(
    {
        "string", "string_literal", "interpreted_string_literal", "raw_string_literal",
        "template_string", "encapsed_string", "string_value", "double_quote_scalar",
        "single_quote_scalar", "plain_scalar",
    }
)  # fmt: skip
_LAST_IDENTIFIER: Final = safe_compile(r"""([A-Za-z_][\w\-]*)["'\s]*$""")


@lru_cache(maxsize=8192)
def is_credential_name(name: str) -> bool:
    """True when ``name`` is a credential word that is not just *about* a credential."""
    words = [word.lower() for word in split_subtokens(name.strip("\"'"))]
    if not words or words[-1] in NON_SECRET_HEADS:
        return False
    if any(word in CREDENTIAL_WORDS for word in words):
        return True
    return any(f"{a}_{b}" in CREDENTIAL_PAIRS for a, b in pairwise(words))


def _is_reference(value: str) -> bool:
    return bool(
        re.fullmatch(r"\$\{[^}]*\}|\$[A-Za-z_]\w*|\{\{[^}]*\}\}|%\([^)]*\)s|\$\([^)]*\)", value)
    )


def _confidence(value: str) -> Confidence:
    if len(value) >= MEDIUM_MIN_LENGTH and not is_placeholder(value):
        return Confidence.MEDIUM
    return Confidence.LOW


def _is_config_file(path: str, language: Language) -> bool:
    name = PurePosixPath(path).name.lower()
    return (
        language in CONFIG_LANGUAGES
        or name.startswith(".env")
        or PurePosixPath(name).suffix in CONFIG_SUFFIXES
    )


def _make_span(offsets: ByteOffsets, start: int, end: int, value: str) -> TypedSpan:
    return TypedSpan(
        kind=PlaceholderKind.SECRET,
        subtype=SUBTYPE,
        start_byte=offsets.at(start),
        end_byte=offsets.at(end),
        confidence=_confidence(value),
        detector=DETECTOR_ID,
    )


def _usable(value: str) -> bool:
    return (
        len(value) >= MIN_VALUE_LENGTH
        and value.lower() not in _KEYWORDS_NOT_STRINGS
        and not _is_reference(value)
    )


class AssignmentDetector:
    """The ``secret.assignment`` detector."""

    id = DETECTOR_ID
    kinds = frozenset({PlaceholderKind.SECRET})

    def detect(self, text: RawCode, *, path: RepoPath, language: Language) -> list[TypedSpan]:
        """Line-based pass: ``name = "value"`` anywhere, and bare values in configuration files."""
        raw = text.expose()
        offsets = ByteOffsets(raw)
        spans: list[TypedSpan] = []
        taken: set[int] = set()
        for match in _ASSIGNMENT.finditer(raw):
            if not is_credential_name(match["name"]):
                continue
            start, end = match.span("quoted")
            value = raw[start + 1 : end - 1]
            if _usable(value):
                taken.add(start)
                spans.append(_make_span(offsets, start + 1, end - 1, value))
        if _is_config_file(path, language):
            for match in _BARE_ASSIGNMENT.finditer(raw):
                value = match["bare"]
                if (
                    not is_credential_name(match["name"])
                    or value[0] in _REFERENCE_START
                    or not _usable(value)
                ):
                    continue
                start, end = match.span("bare")
                spans.append(_make_span(offsets, start, end, value))
        return spans

    def detect_parsed(self, parsed: ParsedFile) -> list[TypedSpan]:
        """Tree-based pass over a parsed file.

        The offsets are those of the text the tree was built from (``parsed.source``), which is
        what the redactor must be given.
        """
        tree = parsed.tree
        if tree is None:
            return self.detect(parsed.source, path=parsed.path, language=parsed.language)
        data = parsed.source.expose().encode("utf-8", errors="surrogatepass")
        spans: list[TypedSpan] = []
        for node in _string_nodes(tree.root_node):
            span = _span_of_assigned_literal(node, data)
            if span is not None:
                spans.append(span)
        return spans


def _string_nodes(root: Any) -> Iterator[Any]:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in _STRING_NODE_TYPES:
            yield node
            continue
        stack.extend(reversed(node.children))


def _assigned_name(node: Any, data: bytes) -> str | None:
    parent = node.parent
    if parent is None:
        return None
    # The assignment target is the first named child of the node that holds the literal: the left
    # side of an assignment, the name of a declarator or keyword argument, the key of a pair. (A
    # nearer sibling can be a type annotation, as in ``const password: string = "..."``.)
    target = next((child for child in parent.children if child.is_named), None)
    if target is None or target.id == node.id:
        return None
    text = data[target.start_byte : target.end_byte].decode("utf-8", errors="replace")
    found = _LAST_IDENTIFIER.search(text.strip())
    return found.group(1) if found else None


def _span_of_assigned_literal(node: Any, data: bytes) -> TypedSpan | None:
    name = _assigned_name(node, data)
    if name is None or not is_credential_name(name):
        return None
    literal = data[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    parts = _LITERAL_PARTS.fullmatch(literal)
    if parts is None:
        body, lead = literal, 0
    else:
        body = parts["body"]
        lead = len(parts["prefix"]) + len(parts["quote"])
    if not _usable(body):
        return None
    start = node.start_byte + len(literal[:lead].encode("utf-8"))
    return TypedSpan(
        kind=PlaceholderKind.SECRET,
        subtype=SUBTYPE,
        start_byte=start,
        end_byte=start + len(body.encode("utf-8")),
        confidence=_confidence(body),
        detector=DETECTOR_ID,
    )


def credential_names(names: Iterable[str]) -> list[str]:
    """The subset of ``names`` that :func:`is_credential_name` accepts (for tests and docs)."""
    return [name for name in names if is_credential_name(name)]
