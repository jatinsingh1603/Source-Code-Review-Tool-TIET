"""Symbol resolution, sanitiser adequacy and the E16-03 matcher additions."""

from pathlib import Path

import pytest

from codekavach.analysis.rules.loader import load_catalogue
from codekavach.analysis.rules.matcher import Matcher
from codekavach.analysis.rules.pack import CatalogueEntry, CatalogueKind
from codekavach.analysis.rules.resolve import import_aliases, symbol_match
from codekavach.core.models import Language
from codekavach.parsing import parse
from tests.support.rules import lines_of, matches_of

PY = Language.PYTHON
JS = Language.JAVASCRIPT
ROOT = Path(__file__).resolve().parents[4]


def sink(entry_id: str, symbol: str) -> CatalogueEntry:
    return CatalogueEntry(id=entry_id, kind=CatalogueKind.SINK, symbol=symbol, arg=0)


def sanitiser(entry_id: str, symbol: str, covers: list[str]) -> CatalogueEntry:
    return CatalogueEntry(
        id=entry_id, kind=CatalogueKind.SANITISER, symbol=symbol, covers=tuple(covers)
    )


def matcher_with(*entries: CatalogueEntry, language: Language = PY) -> Matcher:
    return Matcher(catalogues={entry.id: (language, entry) for entry in entries})


def resolve(code: str, symbol: str, language: Language = PY) -> list[str | None]:
    """The resolution of every call's callee in ``code`` against ``symbol``."""
    parsed = parse("a.py" if language is PY else "a.js", language, code)
    aliases = import_aliases(parsed.tree.root_node, language)  # type: ignore[union-attr]
    found: list[str | None] = []
    stack = [parsed.tree.root_node]  # type: ignore[union-attr]
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.children))
        if node.type in {"call", "call_expression"}:
            callee = node.child_by_field_name("function")
            assert callee is not None
            found.append(symbol_match(symbol, callee, aliases, language))
    return found


def resolved(code: str, symbol: str) -> list[str | None]:
    """JavaScript resolutions without the ``require`` call itself."""
    return [item for item in resolve(code, symbol, JS) if item is not None]


def test_a_plain_import_resolves_exactly() -> None:
    assert resolve("import os\nos.system(c)\n", "os.system") == ["exact"]


def test_an_aliased_import_resolves_exactly() -> None:
    assert resolve("import os as o\no.system(c)\n", "os.system") == ["exact"]
    assert resolve("from os import system as run\nrun(c)\n", "os.system") == ["exact"]


def test_a_from_import_of_a_submodule_resolves() -> None:
    code = "from urllib.request import urlopen\nurlopen(u)\n"
    assert resolve(code, "urllib.request.urlopen") == ["exact"]


def test_a_name_that_shadows_the_library_does_not_resolve() -> None:
    code = "import os\nos = Fake()\nsystem(c)\nos2.system(c)\n"
    assert resolve(code, "os.system")[0] is None
    # a different local object with the same method name is only a partial, lowered match
    assert resolve("def f(os):\n    os.system(c)\n", "os.system") == ["partial"]


def test_an_import_that_resolves_elsewhere_is_a_different_symbol() -> None:
    assert resolve("from mylib import system\nsystem(c)\n", "os.system") == [None]


def test_an_unresolved_receiver_falls_back_to_the_last_two_segments() -> None:
    assert resolve("conn.cursor.execute(q)\n", "sqlite3.cursor.execute") == ["partial"]
    assert resolve("thing.other(q)\n", "os.system") == [None]


def test_builtins_resolve_without_an_import() -> None:
    assert resolve("eval(x)\n", "builtins.eval") == ["exact"]


def test_javascript_require_and_destructuring_resolve() -> None:
    code = 'const cp = require("child_process");\ncp.exec(c);\n'
    assert resolved(code, "child_process.exec") == ["exact"]
    code = 'const { exec: run } = require("child_process");\nrun(c);\n'
    assert resolved(code, "child_process.exec") == ["exact"]
    code = 'import { exec } from "child_process";\nexec(c);\n'
    assert resolved(code, "child_process.exec") == ["exact"]


def test_a_symbol_entry_matches_only_what_resolves_to_it() -> None:
    entry = sink("python.sink.system", "os.system")
    match = {
        "any": [
            {
                "pattern": "$F($X)",
                "where": [{"metavariable": "$F", "catalogue": entry.id}],
            }
        ]
    }
    code = "import os\nos.system(a)\nsubprocess.run(a)\n"
    found = matches_of(code, match, matcher=matcher_with(entry))
    assert lines_of(code, found) == [2]
    assert not found[0].partial


def test_a_partial_resolution_lowers_confidence_and_is_marked() -> None:
    entry = sink("python.sink.system", "os.system")
    match = {
        "any": [{"pattern": "$F($X)", "where": [{"metavariable": "$F", "catalogue": entry.id}]}]
    }
    code = "def f(os):\n    os.system(a)\n"
    found = matches_of(code, match, matcher=matcher_with(entry))
    assert [item.partial for item in found] == [True]


def adequacy(code: str, entries: list[CatalogueEntry], context: str) -> list[int]:
    match = {
        "any": [
            {
                "pattern": "$A + $B",
                "where": [{"metavariable": "$B", "inadequate_for": context}],
            }
        ]
    }
    found = matches_of(code, match, matcher=matcher_with(*entries))
    return lines_of(code, found)


@pytest.fixture
def escapers() -> list[CatalogueEntry]:
    return [
        sanitiser("python.s.html", "markupsafe.escape", ["html"]),
        sanitiser("python.s.both", "html.escape", ["html", "html_attr"]),
        sanitiser("python.s.shell", "shlex.quote", ["shell"]),
    ]


def test_a_sanitiser_for_the_wrong_context_is_inadequate(escapers: list[CatalogueEntry]) -> None:
    code = 'import markupsafe\nx = "<a href=\'" + markupsafe.escape(u)\n'
    assert adequacy(code, escapers, "html_attr") == [2]


def test_a_sanitiser_covering_several_contexts_is_adequate_for_each(
    escapers: list[CatalogueEntry],
) -> None:
    code = 'import html\nx = "<a href=\'" + html.escape(u)\n'
    assert adequacy(code, escapers, "html_attr") == []
    assert adequacy(code, escapers, "html") == []
    assert adequacy(code, escapers, "shell") == [2]


def test_the_wrong_context_property_names_the_sanitiser(escapers: list[CatalogueEntry]) -> None:
    code = 'import markupsafe\nx = "<a href=\'" + markupsafe.escape(u)\n'
    match = {
        "any": [
            {
                "pattern": "$A + $B",
                "where": [{"metavariable": "$B", "inadequate_for": "html_attr"}],
            }
        ]
    }
    found = matches_of(code, match, matcher=matcher_with(*escapers))
    assert dict(found[0].properties) == {
        "sanitiser.inadequate": "markupsafe.escape",
        "sanitiser.required_context": "html_attr",
    }


def test_a_value_that_is_not_a_sanitiser_call_is_not_inadequate(
    escapers: list[CatalogueEntry],
) -> None:
    assert adequacy("x = 'a' + name\n", escapers, "html") == []


def test_two_entries_for_one_symbol_agree_when_either_covers_the_context() -> None:
    entries = [
        sanitiser("python.s.one", "html.escape", ["html"]),
        sanitiser("python.s.two", "html.escape", ["html", "html_attr"]),
    ]
    code = "import html\nx = 'a' + html.escape(u)\n"
    assert adequacy(code, entries, "html_attr") == []


def test_a_wildcard_id_selects_every_entry_with_the_prefix() -> None:
    entries = [sink("python.sink.shell.a", "os.system"), sink("python.sink.shell.b", "os.popen")]
    other = sink("python.sink.other.c", "os.remove")
    match = {
        "any": [
            {
                "pattern": "$F($X)",
                "where": [{"metavariable": "$F", "catalogue": "python.sink.shell.*"}],
            }
        ]
    }
    code = "import os\nos.system(a)\nos.popen(a)\nos.remove(a)\n"
    found = matches_of(code, match, matcher=matcher_with(*entries, other))
    assert lines_of(code, found) == [2, 3]


def test_the_constant_binding_kind_follows_a_module_constant() -> None:
    match = {
        "any": [{"pattern": "f($A)", "where": [{"metavariable": "$A", "kind": "constant_binding"}]}]
    }
    code = 'IV = b"0000"\nf(IV)\nf(os.urandom(16))\n'
    assert lines_of(code, matches_of(code, match)) == [2]


def test_regex_constraints_see_through_one_local_assignment() -> None:
    match = {
        "any": [
            {
                "pattern": "run($X)",
                "where": [{"metavariable": "$X", "not_regex": "quote"}],
            }
        ]
    }
    code = "def f(a):\n    q = shlex.quote(a)\n    run(q)\n    r = a\n    run(r)\n"
    assert lines_of(code, matches_of(code, match)) == [5]


def test_function_regex_requires_text_in_the_enclosing_function() -> None:
    match = {
        "any": [{"pattern": "f($X)", "function_regex": "allowed"}],
    }
    code = "def a(x):\n    allowed = 1\n    f(x)\n\n\ndef b(x):\n    f(x)\n"
    assert lines_of(code, matches_of(code, match)) == [3]


def test_function_regex_in_none_excludes_checked_handlers() -> None:
    match = {
        "any": [{"pattern": "f($X)"}],
        "none": [{"pattern": "f($X)", "function_regex": "allowed"}],
    }
    code = "def a(x):\n    allowed = 1\n    f(x)\n\n\ndef b(x):\n    f(x)\n"
    assert lines_of(code, matches_of(code, match)) == [7]


def test_function_regex_includes_the_decorators_of_a_definition() -> None:
    match = {"any": [{"pattern": "def $F(...): ...", "function_regex": "route"}]}
    code = '@app.route("/a")\ndef a():\n    pass\n\n\ndef b():\n    pass\n'
    assert lines_of(code, matches_of(code, match)) == [2]


def test_a_hotspot_rule_is_reported_with_its_kind() -> None:
    from tests.support.rules import rule_of  # noqa: PLC0415

    rule = rule_of({"any": [{"pattern": "f($X)"}]}, kind="hotspot")
    assert rule.kind == "hotspot"


def test_the_shipped_catalogues_resolve_the_worked_example_symbols() -> None:
    catalogue = load_catalogue(ROOT / "rules" / "mit" / "catalogues" / "python" / "stdlib.yaml")
    symbols = {entry.symbol for entry in catalogue.items()}
    assert {"os.system", "subprocess.run", "pickle.loads", "shlex.quote"} <= symbols
