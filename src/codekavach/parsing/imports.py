"""Import extraction and origin classification (E07-04).

Owning epic: E07.

``extract_imports(parsed)`` finds every import of a Python, JavaScript or TypeScript file,
including the dynamic forms that carry a literal argument, and ``DefaultImportResolver``
classifies the module each one names as ``internal``, ``third_party`` or ``stdlib``.
``attach_imports`` records the result on the file's ``SymbolTable`` so that
``SymbolTable.import_origin(name, scope_id)`` answers "is this name an alias of a third-party API?"
without a second pass.

**Origin versus allowlist.** ``ImportRef.origin`` is a fact about where a *module* comes from.
Whether ``flask.request.args.get`` is a public API is a policy decision about a *name*, which
belongs to the classifier of E09-02. Keep the two apart.

**Asymmetric errors, so the safe direction is "internal".** A module wrongly classified
``third_party`` keeps its names in clear and sends them to the provider (an I6 breach for a module
named after the client's business). A module wrongly classified ``internal`` only costs the model
a recognisable name. So a module string that cannot be understood at all (empty, over-long,
malformed) is classified ``internal`` and flagged ``conservative``; the stage counts those. The
rules otherwise follow the documented order and are deterministic: they read the project tree and
two bundled name lists, never the environment of the machine that runs the scan.

Untrusted input: ``tsconfig.json`` and ``package.json`` come from the scanned repository. They
are read with a size cap, parsed as data (comments and trailing commas tolerated), unknown fields
are ignored, nothing is executed, and a path is never followed outside the project root.
"""

import importlib.resources
import json
import re
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, Literal, NamedTuple, Protocol

from tree_sitter import Node

from codekavach.core.models import DataClassification, KavachModel, Language, Location
from codekavach.parsing.models import ParsedFile

if TYPE_CHECKING:
    from codekavach.parsing.symbols import SymbolTable

Origin = Literal["internal", "third_party", "stdlib"]

MAX_CONFIG_BYTES: Final = 256 * 1024
MAX_MODULE_LENGTH: Final = 512
DATA_PACKAGE: Final = "codekavach.parsing.data"
_PYTHON_ROOTS: Final = ("", "src")
_JS_SUFFIXES: Final = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_PY_MODULE: Final = re.compile(r"\.+|\.*[^\W\d]\w*(\.[^\W\d]\w*)*")
_JS_SPECIFIER: Final = re.compile(r"(@[\w.~-]+/)?[\w.~-]+(/[^\s\\]*)?")


class UnsupportedLanguage(ValueError):  # noqa: N818 - named by the issue
    """No import rules exist for this language yet (E07-05 adds the others)."""

    def __init__(self, language: Language) -> None:
        self.language = language
        super().__init__(f"no import rules for language {language.value!r}")


class ImportRef(KavachModel):
    """One import: where it points, where it comes from, and the local name it binds.

    ``module`` is the module as written (``a.b``, ``..pkg``, ``./engine``, ``node:fs``).
    ``imported`` is the member taken from it (``c`` in ``from a.b import c``, ``*`` for a wildcard
    or namespace import), ``bound`` the local name introduced and ``alias`` the ``as`` name, if
    any. ``scope_id`` is the scope the bound name lives in. ``conservative`` is true when the
    origin is ``internal`` only because the module string could not be classified.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    module: str
    origin: Origin
    alias: str | None = None
    location: Location
    imported: str | None = None
    bound: str | None = None
    scope_id: int = 0
    conservative: bool = False


class Classification(NamedTuple):
    """The origin of a module and whether it was a conservative guess."""

    origin: Origin
    conservative: bool


class ImportResolver(Protocol):
    """Classifies the module an import names."""

    def classify(self, module: str, *, project_root: Path) -> Origin:
        """``internal``, ``third_party`` or ``stdlib`` for ``module``; never raises."""
        ...


class RawImport(NamedTuple):
    """An import as the syntax tree states it, before classification."""

    module: str
    alias: str | None
    imported: str | None
    bound: str | None
    bound_start: int | None
    start: int
    end: int


# --- extraction ----------------------------------------------------------------------------


def _text(node: Node | None) -> str:
    return "" if node is None else (node.text or b"").decode("utf-8", errors="replace")


def _fielded(node: Node) -> list[tuple[Node, str | None]]:
    return [
        (child, node.field_name_for_child(index))
        for index, child in enumerate(node.children)
        if child.is_named
    ]


def _first_identifier(node: Node) -> Node | None:
    if node.type == "identifier":
        return node
    return next((c for c in node.named_children if c.type == "identifier"), None)


def _python_string(node: Node | None) -> str | None:
    """The text of a plain string literal (no f-string, no bytes), else ``None``."""
    if node is None or node.type != "string":
        return None
    start = next((c for c in node.children if c.type == "string_start"), None)
    if start is None or set(_text(start).lower()) & {"f", "b"}:
        return None
    parts = [c for c in node.named_children if c.type not in ("string_start", "string_end")]
    if any(c.type != "string_content" for c in parts) or len(parts) > 1:
        return None
    return _text(parts[0]) if parts else ""


def _assigned_to(node: Node) -> Node | None:
    parent = node.parent
    if parent is not None and parent.type == "assignment":
        left = parent.child_by_field_name("left")
        return left if left is not None and left.type == "identifier" else None
    return None


def _import_of(
    module: str,
    *,
    imported: str | None = None,
    bound: Node | None = None,
    alias: Node | None = None,
    span: Node,
) -> RawImport:
    return RawImport(
        module=module,
        alias=_text(alias) or None,
        imported=imported,
        bound=_text(bound) or None,
        bound_start=None if bound is None else bound.start_byte,
        start=span.start_byte,
        end=span.end_byte,
    )


def _python_import_statement(node: Node) -> list[RawImport]:
    found: list[RawImport] = []
    for child, field in _fielded(node):
        if field != "name":
            continue
        if child.type == "aliased_import":
            target = child.child_by_field_name("name")
            alias = child.child_by_field_name("alias")
            found.append(_import_of(_text(target), bound=alias, alias=alias, span=node))
        else:
            found.append(_import_of(_text(child), bound=_first_identifier(child), span=node))
    return found


def _python_member(child: Node, module: str, node: Node, *, binds: bool) -> RawImport:
    if child.type == "aliased_import":
        target = child.child_by_field_name("name")
        alias = child.child_by_field_name("alias")
        return _import_of(
            module,
            imported=_text(target),
            bound=alias if binds else None,
            alias=alias,
            span=node,
        )
    bound = _first_identifier(child) if binds else None
    return _import_of(module, imported=_text(child), bound=bound, span=node)


def _python_from_import(node: Node) -> list[RawImport]:
    module_node = node.child_by_field_name("module_name")
    module = "".join(_text(module_node).split())
    binds = node.type != "future_import_statement"
    if node.type == "future_import_statement":
        module = "__future__"
    found = [
        _python_member(child, module, node, binds=binds)
        for child, field in _fielded(node)
        if field == "name"
    ]
    if any(c.type == "wildcard_import" for c in node.named_children):
        found.append(_import_of(module, imported="*", span=node))
    return found


def _python_call(node: Node) -> list[RawImport]:
    function = node.child_by_field_name("function")
    name = "".join(_text(function).split())
    if name not in ("__import__", "importlib.import_module"):
        return []
    arguments = node.child_by_field_name("arguments")
    first = next(iter(arguments.named_children), None) if arguments is not None else None
    module = _python_string(first)
    if not module:
        return []
    return [_import_of(module, bound=_assigned_to(node), span=node)]


_PYTHON_HANDLERS: Final = {
    "import_statement": _python_import_statement,
    "import_from_statement": _python_from_import,
    "future_import_statement": _python_from_import,
    "call": _python_call,
}


def _js_literal(node: Node | None) -> str | None:
    """The value of a plain string (or substitution-free template) literal, else ``None``."""
    if node is None:
        return None
    if node.type == "string":
        parts = [c for c in node.named_children if c.type != "comment"]
        if any(c.type != "string_fragment" for c in parts):
            return None
        return "".join(_text(c) for c in parts)
    if node.type == "template_string":
        if any(c.type != "string_fragment" for c in node.named_children):
            return None
        return _text(node).strip("`")
    return None


def _js_clause(clause: Node, module: str, node: Node) -> list[RawImport]:
    found: list[RawImport] = []
    for child in clause.named_children:
        if child.type == "identifier":
            found.append(_import_of(module, imported="default", bound=child, span=node))
        elif child.type == "namespace_import":
            found.append(
                _import_of(module, imported="*", bound=_first_identifier(child), span=node)
            )
        elif child.type == "named_imports":
            for spec in child.named_children:
                name = spec.child_by_field_name("name")
                alias = spec.child_by_field_name("alias")
                found.append(
                    _import_of(
                        module, imported=_text(name), bound=alias or name, alias=alias, span=node
                    )
                )
    return found


def _js_import_statement(node: Node) -> list[RawImport]:
    source = node.child_by_field_name("source")
    clause = next((c for c in node.named_children if c.type == "import_clause"), None)
    require = next((c for c in node.named_children if c.type == "import_require_clause"), None)
    if require is not None:
        module = _js_literal(require.child_by_field_name("source"))
        bound = _first_identifier(require)
        return [] if not module else [_import_of(module, imported="*", bound=bound, span=node)]
    module = _js_literal(source)
    if not module:
        return []
    if clause is None:
        return [_import_of(module, span=node)]
    return _js_clause(clause, module, node)


def _js_export_statement(node: Node) -> list[RawImport]:
    module = _js_literal(node.child_by_field_name("source"))
    if not module:
        return []
    clause = next((c for c in node.named_children if c.type == "export_clause"), None)
    if clause is None:
        return [_import_of(module, imported="*", span=node)]
    return [
        _import_of(module, imported=_text(spec.child_by_field_name("name")), span=node)
        for spec in clause.named_children
    ]


def _pattern_bindings(pattern: Node) -> list[tuple[str, Node]]:
    """``(imported name, bound node)`` for each name a destructuring pattern binds."""
    found: list[tuple[str, Node]] = []
    for child in pattern.named_children:
        if child.type == "shorthand_property_identifier_pattern":
            found.append((_text(child), child))
        elif child.type == "pair_pattern":
            key, value = child.child_by_field_name("key"), child.child_by_field_name("value")
            if key is not None and value is not None and value.type == "identifier":
                found.append((_text(key), value))
    return found


def _js_binding_target(node: Node) -> Node | None:
    """The ``variable_declarator`` an ``await``-wrapped or plain call initialises, if any."""
    parent = node.parent
    while parent is not None and parent.type in ("await_expression", "parenthesized_expression"):
        parent = parent.parent
    if parent is not None and parent.type == "variable_declarator":
        return parent.child_by_field_name("name")
    return None


def _js_call(node: Node) -> list[RawImport]:
    function = node.child_by_field_name("function")
    if function is None or (function.type != "import" and _text(function) != "require"):
        return []
    arguments = node.child_by_field_name("arguments")
    first = next(iter(arguments.named_children), None) if arguments is not None else None
    module = _js_literal(first)
    if not module:
        return []
    target = _js_binding_target(node)
    if target is not None and target.type == "object_pattern":
        bindings = _pattern_bindings(target)
        return [
            _import_of(module, imported=name, bound=bound, span=node) for name, bound in bindings
        ]
    return [_import_of(module, bound=target, span=node)]


_JS_HANDLERS: Final = {
    "import_statement": _js_import_statement,
    "export_statement": _js_export_statement,
    "call_expression": _js_call,
}


def _dotted(node: Node) -> list[Node]:
    """The identifier leaves of a Java qualified name, left to right."""
    if node.type == "identifier":
        return [node]
    leaves: list[Node] = []
    for child in node.named_children:
        leaves.extend(_dotted(child))
    return leaves


def _java_import(node: Node) -> list[RawImport]:
    """``import a.b.C;`` is module ``a.b`` taking ``C``; ``import a.b.*;`` is module ``a.b``."""
    leaves = _dotted(node)
    if not leaves:
        return []
    wildcard = any(child.type == "asterisk" for child in node.children)
    if wildcard:
        return [_import_of(".".join(_text(x) for x in leaves), imported="*", span=node)]
    if len(leaves) == 1:
        return [_import_of(_text(leaves[0]), bound=leaves[0], span=node)]
    module = ".".join(_text(x) for x in leaves[:-1])
    return [_import_of(module, imported=_text(leaves[-1]), bound=leaves[-1], span=node)]


_JAVA_HANDLERS: Final = {"import_declaration": _java_import}

_GO_VERSION_SUFFIX: Final = re.compile(r"v\d+")


def _go_default_name(path: str) -> str | None:
    """The package name an import without an alias binds: the last path element, not ``v2``."""
    parts = [part for part in path.split("/") if part]
    if parts and _GO_VERSION_SUFFIX.fullmatch(parts[-1]) and len(parts) > 1:
        parts.pop()
    if not parts:
        return None
    name = parts[-1].removeprefix("go-").removesuffix(".go").replace("-", "_").replace(".", "_")
    return name if name.isidentifier() else None


def _go_import_spec(node: Node) -> list[RawImport]:
    path_node = node.child_by_field_name("path")
    if path_node is None:
        return []
    path = "".join(_text(c) for c in path_node.children if c.type.endswith("_content"))
    if not path:
        return []
    name = node.child_by_field_name("name")
    if name is not None and name.type == "package_identifier":
        return [_import_of(path, bound=name, alias=name, span=node)]
    if name is not None and name.type == "dot":
        return [_import_of(path, imported="*", span=node)]
    if name is not None:
        return [_import_of(path, span=node)]  # imported for its side effects: binds nothing
    default = _go_default_name(path)
    return [RawImport(path, None, None, default, None, node.start_byte, node.end_byte)]


_GO_HANDLERS: Final = {"import_spec": _go_import_spec}


def _leaf_names(node: Node, types: frozenset[str]) -> list[Node]:
    if node.type in types:
        return [node]
    found: list[Node] = []
    for child in node.named_children:
        found.extend(_leaf_names(child, types))
    return found


_KOTLIN_NAMES: Final = frozenset({"simple_identifier"})


def _kotlin_import(node: Node) -> list[RawImport]:
    """``import a.b.C`` is module ``a.b`` taking ``C``; ``import a.b.C as D`` binds ``D``."""
    path = next((c for c in node.named_children if c.type == "identifier"), None)
    if path is None:
        return []
    leaves = _leaf_names(path, _KOTLIN_NAMES)
    alias = next(
        (c for a in node.named_children if a.type == "import_alias" for c in a.named_children),
        None,
    )
    if not leaves:
        return []
    if any(not c.is_named and c.type == "*" for c in node.children):
        return [_import_of(".".join(_text(x) for x in leaves), imported="*", span=node)]
    if len(leaves) == 1:
        return [_import_of(_text(leaves[0]), bound=alias or leaves[0], span=node)]
    module = ".".join(_text(x) for x in leaves[:-1])
    return [
        _import_of(
            module,
            imported=_text(leaves[-1]),
            bound=alias or leaves[-1],
            alias=alias,
            span=node,
        )
    ]


_KOTLIN_HANDLERS: Final = {"import_header": _kotlin_import}

_CS_NAMES: Final = frozenset({"identifier"})


def _csharp_using(node: Node) -> list[RawImport]:
    """``using A.B;`` imports a namespace; ``using X = A.B;`` binds the alias ``X``."""
    alias = node.child_by_field_name("name")
    target = next((c for c in node.named_children if alias is None or c.id != alias.id), None)
    if target is None or any(not c.is_named and c.type == "static" for c in node.children):
        return []
    module = ".".join(_text(x) for x in _leaf_names(target, _CS_NAMES))
    if not module:
        return []
    if alias is not None:
        return [_import_of(module, bound=alias, alias=alias, span=node)]
    return [_import_of(module, imported="*", span=node)]


_CSHARP_HANDLERS: Final = {"using_directive": _csharp_using}


_NO_IMPORT_RULES: Final = frozenset({Language.PHP, Language.RUBY, Language.C, Language.CPP})


def extract_imports(parsed: ParsedFile) -> tuple[RawImport, ...]:
    """Every import of ``parsed`` in source order, from one pass over its syntax tree.

    Raises:
        UnsupportedLanguage: ``parsed.language`` has no import rules.
    """
    if parsed.language is Language.PYTHON:
        handlers = _PYTHON_HANDLERS
    elif parsed.language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        handlers = _JS_HANDLERS
    elif parsed.language is Language.JAVA:
        handlers = _JAVA_HANDLERS
    elif parsed.language is Language.GO:
        handlers = _GO_HANDLERS
    elif parsed.language is Language.KOTLIN:
        handlers = _KOTLIN_HANDLERS
    elif parsed.language is Language.CSHARP:
        handlers = _CSHARP_HANDLERS
    elif parsed.language in _NO_IMPORT_RULES:
        return ()  # PHP, Ruby, C and C++ imports are left to the name-level classification
    else:
        raise UnsupportedLanguage(parsed.language)
    if parsed.tree is None:
        return ()
    found: list[RawImport] = []
    stack = [parsed.tree.root_node]
    while stack:
        node = stack.pop()
        handler = handlers.get(node.type)
        if handler is not None:
            found.extend(handler(node))
        stack.extend(reversed(node.named_children))
    found.sort(key=lambda raw: (raw.start, raw.bound_start or 0))
    return tuple(found)


# --- classification ------------------------------------------------------------------------


@cache
def _name_list(filename: str) -> frozenset[str]:
    text = (importlib.resources.files(DATA_PACKAGE) / filename).read_text(encoding="utf-8")
    return frozenset(
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


def python_stdlib_names() -> frozenset[str]:
    """Top-level standard-library module names bundled with CodeKavach."""
    return _name_list("python_stdlib.txt")


def node_builtin_names() -> frozenset[str]:
    """Node.js built-in module names bundled with CodeKavach (subpaths such as ``fs/promises``)."""
    return _name_list("node_builtins.txt")


def _strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments and trailing commas, leaving strings untouched."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(char)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _read_json(path: Path) -> dict[str, object]:
    """A JSON object from ``path``, or ``{}`` if it is missing, too large or malformed."""
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return {}
        data = json.loads(_strip_jsonc(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _pattern(text: str) -> re.Pattern[str]:
    return re.compile("^" + ".*".join(re.escape(part) for part in text.split("*")) + "$")


class _JsConfig(NamedTuple):
    patterns: tuple[re.Pattern[str], ...]
    base_url: Path | None


def _contained(root: Path, relative: str) -> Path | None:
    try:
        resolved = (root / relative).resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return resolved


def _load_js_config(root: Path) -> _JsConfig:
    patterns: list[re.Pattern[str]] = []
    base_url: Path | None = None
    for name in ("tsconfig.json", "jsconfig.json"):
        options = _read_json(root / name).get("compilerOptions")
        if not isinstance(options, dict):
            continue
        paths = options.get("paths")
        if isinstance(paths, dict):
            patterns.extend(_pattern(key) for key in paths if isinstance(key, str))
        base = options.get("baseUrl")
        if isinstance(base, str) and base_url is None:
            base_url = _contained(root, base)
    imports = _read_json(root / "package.json").get("imports")
    if isinstance(imports, dict):
        patterns.extend(_pattern(key) for key in imports if isinstance(key, str))
    return _JsConfig(tuple(patterns), base_url)


_RESOLVABLE: Final = frozenset(
    {
        Language.PYTHON,
        Language.JAVASCRIPT,
        Language.TYPESCRIPT,
        Language.JAVA,
        Language.GO,
        Language.KOTLIN,
        Language.CSHARP,
        Language.PHP,
        Language.RUBY,
        Language.C,
        Language.CPP,
    }
)
# The first segment of an import that is the platform's own, for the languages that classify by it.
_PLATFORM_ROOTS: Final = {
    Language.KOTLIN: frozenset({"java", "javax", "kotlin", "kotlinx", "android", "androidx"}),
    Language.CSHARP: frozenset({"System", "Microsoft", "Windows"}),
}
_JAVA_NAME: Final = re.compile(r"[^\W\d]\w*(\.[^\W\d]\w*)*")
_JAVA_PLATFORM: Final = frozenset({"java", "javax", "jdk"})
_JAVA_ROOTS: Final = ("", "src/main/java", "src/test/java", "src", "app/src/main/java")
_GO_PATH: Final = re.compile(r"[\w.~+-]+(/[\w.~+-]+)*|\.{1,2}(/[\w.~+-]+)*")
_GO_MODULE_LINE: Final = re.compile(r"^module\s+(\S+)\s*$", re.MULTILINE)


def _read_go_module(root: Path) -> str | None:
    """The ``module`` path of ``root/go.mod``; the file is untrusted data and never executed."""
    try:
        with (root / "go.mod").open("rb") as handle:
            head = handle.read(MAX_CONFIG_BYTES)
    except OSError:
        return None
    match = _GO_MODULE_LINE.search(head.decode("utf-8", errors="replace"))
    if match is None:
        return None
    return match.group(1).strip('"')


class DefaultImportResolver:
    """Classifies module strings for one language by the rules in the E07-04 issue.

    ``internal_names`` adds top-level names the caller already knows are the project's own (the
    stage passes the top-level directories and modules of the scanned files), which keeps a
    monorepo package that is not directly under ``project_root`` from being treated as a
    dependency.
    """

    def __init__(self, language: Language, *, internal_names: Iterable[str] = ()) -> None:
        if language not in _RESOLVABLE:
            raise UnsupportedLanguage(language)
        self.language = language
        self._internal_names = frozenset(internal_names)
        self._config: dict[Path, _JsConfig] = {}
        self._on_disk: dict[tuple[Path, str], bool] = {}
        self._go_modules: dict[Path, str | None] = {}

    def classify(self, module: str, *, project_root: Path) -> Origin:
        """``internal``, ``third_party`` or ``stdlib`` for ``module``; never raises."""
        return self.classify_detailed(module, project_root=project_root).origin

    def classify_detailed(  # noqa: PLR0911 - one return per language
        self, module: str, *, project_root: Path
    ) -> Classification:
        """Like :meth:`classify`, saying whether the answer was a conservative guess."""
        text = module.strip()
        if not text or len(text) > MAX_MODULE_LENGTH or any(ord(c) < 32 for c in text):
            return Classification("internal", True)
        try:
            if self.language is Language.PYTHON:
                return self._python(text, project_root)
            if self.language is Language.JAVA:
                return self._java(text, project_root)
            if self.language is Language.GO:
                return self._go(text, project_root)
            if self.language in _PLATFORM_ROOTS or self.language in _NO_IMPORT_RULES:
                return self._platform(text)
            return self._javascript(text, project_root)
        except (OSError, ValueError):
            return Classification("internal", True)

    def _exists(self, root: Path, relative: str) -> bool:
        key = (root, relative)
        if key not in self._on_disk:
            target = _contained(root, relative)
            self._on_disk[key] = target is not None and (
                target.is_dir() or target.with_name(target.name + ".py").is_file()
            )
        return self._on_disk[key]

    def _python(self, text: str, root: Path) -> Classification:
        if _PY_MODULE.fullmatch(text) is None:
            return Classification("internal", True)
        if text.startswith("."):
            return Classification("internal", False)
        top = text.split(".", 1)[0]
        if top in self._internal_names or any(
            self._exists(root / base if base else root, top) for base in _PYTHON_ROOTS
        ):
            return Classification("internal", False)
        if top in python_stdlib_names():
            return Classification("stdlib", False)
        return Classification("third_party", False)

    def _java(self, text: str, root: Path) -> Classification:
        """Classify a Java package: the platform, a project source root, or a dependency."""
        if _JAVA_NAME.fullmatch(text) is None:
            return Classification("internal", True)
        top = text.split(".", 1)[0]
        if top in _JAVA_PLATFORM:
            return Classification("stdlib", False)
        if top in self._internal_names or any(
            self._dir_exists(root, base, text.replace(".", "/")) for base in _JAVA_ROOTS
        ):
            return Classification("internal", False)
        return Classification("third_party", False)

    def _platform(self, text: str) -> Classification:
        """Kotlin and C#: the platform's own namespaces, the project's, or a dependency's."""
        if self.language in _NO_IMPORT_RULES or _JAVA_NAME.fullmatch(text) is None:
            return Classification("internal", True)
        top = text.split(".", 1)[0]
        if top in _PLATFORM_ROOTS[self.language]:
            return Classification("stdlib", False)
        if top in self._internal_names:
            return Classification("internal", False)
        return Classification("third_party", False)

    def _dir_exists(self, root: Path, base: str, relative: str) -> bool:
        key = (root, f"{base}|{relative}")
        if key not in self._on_disk:
            target = _contained(root, f"{base}/{relative}" if base else relative)
            self._on_disk[key] = target is not None and target.is_dir()
        return self._on_disk[key]

    def _go(self, text: str, root: Path) -> Classification:
        """Classify a Go import path: standard library, the go.mod module, or a dependency."""
        if _GO_PATH.fullmatch(text) is None:
            return Classification("internal", True)
        if text.startswith("."):
            return Classification("internal", False)
        first = text.split("/", 1)[0]
        module = self._go_module(root)
        if module and (text == module or text.startswith(module + "/")):
            return Classification("internal", False)
        if first in self._internal_names:
            return Classification("internal", False)
        if "." not in first:
            return Classification("stdlib", False)
        return Classification("third_party", False)

    def _go_module(self, root: Path) -> str | None:
        """The module path of ``go.mod``: read with a size cap, the ``module`` line only."""
        if root not in self._go_modules:
            self._go_modules[root] = _read_go_module(root)
        return self._go_modules[root]

    def _js_config(self, root: Path) -> _JsConfig:
        if root not in self._config:
            self._config[root] = _load_js_config(root)
        return self._config[root]

    def _javascript(self, text: str, root: Path) -> Classification:
        if text.startswith((".", "/", "#")):
            return Classification("internal", False)
        if text.startswith("node:") or text in node_builtin_names():
            return Classification("stdlib", False)
        if _JS_SPECIFIER.fullmatch(text) is None:
            return Classification("internal", True)
        config = self._js_config(root)
        first = text.split("/", 1)[0]
        if first in self._internal_names or any(p.match(text) for p in config.patterns):
            return Classification("internal", False)
        if config.base_url is not None and self._under_base(config.base_url, first):
            return Classification("internal", False)
        return Classification("third_party", False)

    def _under_base(self, base: Path, first: str) -> bool:
        key = (base, first)
        if key not in self._on_disk:
            self._on_disk[key] = (base / first).is_dir() or any(
                (base / f"{first}{suffix}").is_file() for suffix in _JS_SUFFIXES
            )
        return self._on_disk[key]


# --- attaching the result to a symbol table ------------------------------------------------


def attach_imports(
    table: "SymbolTable",
    parsed: ParsedFile,
    resolver: ImportResolver,
    *,
    project_root: Path,
) -> "SymbolTable":
    """A copy of ``table`` whose ``imports`` hold every import of ``parsed``, classified.

    Raises:
        UnsupportedLanguage: ``parsed.language`` has no import rules.
    """
    raws = extract_imports(parsed)
    line_index = parsed.line_index
    if not raws or line_index is None:
        return table
    scope_by_start = {
        (s.location.start_line, s.location.start_col or 0): s.scope_id for s in table.symbols
    }
    detailed = resolver.classify_detailed if isinstance(resolver, DefaultImportResolver) else None
    locations = line_index.locations(parsed.path, [(raw.start, raw.end) for raw in raws])
    refs: list[ImportRef] = []
    for raw, location in zip(raws, locations, strict=True):
        if detailed is not None:
            verdict = detailed(raw.module, project_root=project_root)
        else:
            verdict = Classification(
                resolver.classify(raw.module, project_root=project_root), False
            )
        scope = 0
        if raw.bound_start is not None:
            scope = max(scope_by_start.get(line_index.position(raw.bound_start), 0), 0)
        refs.append(
            ImportRef(
                module=raw.module,
                origin=verdict.origin,
                alias=raw.alias,
                location=location,
                imported=raw.imported,
                bound=raw.bound,
                scope_id=scope,
                conservative=verdict.conservative,
            )
        )
    return table.model_copy(update={"imports": tuple(refs)})


__all__ = [
    "Classification",
    "DefaultImportResolver",
    "ImportRef",
    "ImportResolver",
    "Origin",
    "RawImport",
    "UnsupportedLanguage",
    "attach_imports",
    "extract_imports",
    "node_builtin_names",
    "python_stdlib_names",
]
