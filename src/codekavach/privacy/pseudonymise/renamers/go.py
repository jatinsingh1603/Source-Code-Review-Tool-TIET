"""The Go renamer (E09-06).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers package-level declarations (exported and unexported alike: export is
visibility, not public API), method receivers, struct fields, interface method sets, ``:=``
declarations, parameters and results. The blank identifier and the predeclared names are kept by
the classification. Two places need more than a plain rename:

**Struct tags.** A tag names the wire or column a field maps to (``json:"festivalBonus"``).
Renaming the field and leaving the tag leaks the name; renaming them differently breaks the
contract the reviewer needs to see. The rule is: the tag keys (``json``, ``db``, ``validate``)
stay in clear, the name a name-bearing key carries becomes the field's token so the two agree,
options such as ``omitempty`` stay, and the arguments of other keys are kept only when they are
rule words or numbers (``required``, ``min=3``); anything else becomes the token. A tag on a
field that stays in clear is shaped as ordinary text.

**Import paths.** An import path is kept when it names a standard-library package or a listed
module, so a reviewer still sees ``database/sql``, and is shaped otherwise.
"""

import re
from functools import lru_cache
from typing import Final

from tree_sitter import Query, QueryCursor

from codekavach.core.models import Language
from codekavach.parsing.loader import load_language
from codekavach.parsing.models import ParsedFile
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.allowlist import PublicAllowlist
from codekavach.privacy.pseudonymise.plan import EditReason, RenameEdit
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer, SourceFacts

_QUERY = """
(import_spec path: (_) @specifier)
(field_declaration name: (field_identifier) @field tag: (_) @tag)
"""
# The top-level directories of the Go standard library. A path whose first element is not here is
# not treated as standard library: a module path without a dot may be the client's own.
STDLIB_ROOTS: Final = frozenset(
    {
        "archive", "bufio", "bytes", "cmp", "compress", "container", "context", "crypto",
        "database", "debug", "embed", "encoding", "errors", "expvar", "flag", "fmt", "go", "hash",
        "html", "image", "index", "io", "iter", "log", "maps", "math", "mime", "net", "os", "path",
        "plugin", "reflect", "regexp", "runtime", "slices", "sort", "strconv", "strings",
        "structs", "sync", "syscall", "testing", "text", "time", "unicode", "unique", "unsafe",
    }
)  # fmt: skip
# Keys whose first comma-separated part is a name on the wire or in a column.
NAME_KEYS: Final = frozenset(
    {
        "json", "db", "yaml", "xml", "toml", "mapstructure", "form", "bson", "query", "uri",
        "header", "param", "csv", "env", "ini", "msgpack", "protobuf", "gorm_name",
    }
)  # fmt: skip
# Options after the name that are part of the key's grammar and carry no client name.
SAFE_OPTIONS: Final = frozenset(
    {"omitempty", "omitzero", "string", "inline", "attr", "chardata", "cdata", "comment",
     "innerxml", "any", "anyattr", "flow", "required", "squash", "remain"}
)  # fmt: skip
# Rule words of validation and ORM keys that are kept as written.
SAFE_RULES: Final = frozenset(
    {"required", "omitempty", "min", "max", "len", "gte", "lte", "gt", "lt", "eq", "ne", "email",
     "url", "uri", "uuid", "alpha", "alphanum", "numeric", "dive", "oneof", "unique", "primaryKey",
     "primary_key", "autoIncrement", "not", "null", "default", "index", "uniqueIndex", "size",
     "type", "autoCreateTime", "autoUpdateTime", "omitnil", "isdefault", "ascii", "base64",
     "boolean", "datetime", "hostname", "ip", "ipv4", "ipv6", "json", "lowercase", "uppercase"}
)  # fmt: skip
_PAIR: Final = re.compile(r'([\w.-]+):"((?:[^"\\]|\\.)*)"')
_NUMBER: Final = re.compile(r"-?[0-9.]+")


@lru_cache(maxsize=1)
def _query() -> Query:
    return Query(load_language(Language.GO), _QUERY)


def rewrite_tag(tag: str, token: str) -> str:
    """``tag`` with every name replaced by ``token``; the keys and the grammar stay."""
    out: list[str] = []
    position = 0
    for match in _PAIR.finditer(tag):
        out.append(tag[position : match.start()])
        key, value = match.group(1), match.group(2)
        out.append(f'{key}:"{_value(key, value, token)}"')
        position = match.end()
    rest = tag[position:]
    if rest.strip():
        return token  # not the key:"value" form: nothing in it can be told from a name
    out.append(rest)
    return "".join(out)


def _value(key: str, value: str, token: str) -> str:
    if key in NAME_KEYS:
        head, *options = value.split(",")
        kept = [option for option in options if option in SAFE_OPTIONS]
        name = head if head in {"", "-"} else token
        return ",".join([name, *kept])
    pieces = re.split(r"([,;|])", value)
    for index in range(0, len(pieces), 2):
        pieces[index] = _rule(pieces[index], token)
    return "".join(pieces)


def _rule(part: str, token: str) -> str:
    separator = ":" if ":" in part else "="
    head, found, rest = part.partition(separator)
    word = head.strip()
    if not word:
        return part
    if not found and all(piece in SAFE_RULES for piece in word.split()):
        return part
    if found and word in SAFE_RULES and _NUMBER.fullmatch(rest):
        return part
    if found and word == "column":
        return f"{head}{found}{token}"
    return token


class GoRenamer(BaseRenamer):
    """Renames the internal identifiers of a Go file."""

    language = Language.GO

    def facts(self, parsed: ParsedFile) -> SourceFacts:
        """The start of each import path and of each struct tag, with its field."""
        if parsed.tree is None:
            raise PseudonymError("a file without a syntax tree is not renamed")
        captures = QueryCursor(_query()).captures(parsed.tree.root_node)
        tags: dict[int, str] = {}
        fields = {node.parent.id if node.parent else -1: node for node in captures.get("field", [])}
        for node in captures.get("tag", []):
            parent = node.parent
            field = fields.get(parent.id) if parent is not None else None
            if field is not None:
                tags[node.start_byte + 1] = (field.text or b"").decode("utf-8")
        return SourceFacts(
            specifier_starts=frozenset(
                node.start_byte + 1 for node in captures.get("specifier", [])
            ),
            tag_fields=tuple(sorted(tags.items())),
        )

    def is_public_specifier(self, content: str, allowlist: PublicAllowlist) -> bool:
        """A standard-library path, or a module the bundled data lists."""
        parts = content.split("/")
        if parts[0] in STDLIB_ROOTS:
            return True
        key = "/".join(parts[:3]) if "." in parts[0] else content
        return key in allowlist.package_names()

    def literal_edits(
        self, original: str, start: int, end: int, tokens: dict[str, str], facts: SourceFacts
    ) -> list[RenameEdit] | None:
        """A struct tag follows its field's token; every other string takes the common path."""
        for tag_start, field in facts.tag_fields:
            if tag_start != start:
                continue
            token = tokens.get(field)
            if token is None:
                return None  # the field stays in clear, so its tag is shaped like any text
            new = rewrite_tag(original, token)
            return [] if new == original else [RenameEdit(start, end, new, EditReason.NAME_STRING)]
        return None
