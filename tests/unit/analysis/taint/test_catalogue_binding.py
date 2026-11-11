"""Binding of catalogue entries to calls and places (E17-02)."""

import pytest

from codekavach.analysis.taint.catalogue import Binding
from codekavach.analysis.taint.ir import Call, Place
from codekavach.core.models import Language
from tests.support.taint import calls, function_of, lower_source, shipped_catalogues

JS = Language.JAVASCRIPT


def binding(code: str, language: Language = Language.PYTHON) -> tuple[Binding, list[Call]]:
    module = lower_source(code, language)
    function = function_of(module, "f")
    return Binding(shipped_catalogues(), module.aliases, language.value), calls(function)


def test_a_resolved_symbol_matches_a_sink_exactly() -> None:
    bound, found = binding("import os\n\ndef f(x):\n    os.system(x)\n")
    match = bound.sink_for(found[0])
    assert match is not None and match.exact and match.kind == "shell" and match.arg == 0


def test_an_aliased_import_still_resolves() -> None:
    bound, found = binding("import subprocess as sp\n\ndef f(x):\n    sp.run(x)\n")
    match = bound.sink_for(found[0])
    assert (
        match is not None and match.exact and match.entry.id == "python.sink.shell.subprocess.run"
    )


def test_a_from_import_resolves() -> None:
    bound, found = binding("from os import system as run\n\ndef f(x):\n    run(x)\n")
    assert bound.sink_for(found[0]) is not None


def test_a_builtin_matches_by_its_bare_name() -> None:
    bound, found = binding("def f(x):\n    open(x)\n")
    match = bound.sink_for(found[0])
    assert match is not None and match.exact and match.kind == "path"


def test_a_class_method_entry_matches_by_method_name_and_says_so() -> None:
    bound, found = binding("def f(cur, q):\n    cur.execute(q)\n")
    match = bound.sink_for(found[0])
    assert match is not None and not match.exact and match.kind == "sql"


def test_a_method_name_match_needs_a_receiver() -> None:
    bound, found = binding("def f(q):\n    execute(q)\n")
    assert bound.sink_for(found[0]) is None


def test_a_name_that_only_looks_like_a_sink_is_not_one() -> None:
    bound, found = binding("def f(x):\n    mine.system(x)\n")
    assert bound.sink_for(found[0]) is None


def test_only_a_catalogue_entry_sanitises() -> None:
    bound, found = binding("import html\n\ndef f(x):\n    html.escape(x)\n    safe_escape(x)\n")
    assert bound.sanitiser_for(found[0]) is not None
    assert bound.sanitiser_for(found[1]) is None


def test_a_source_symbol_matches_its_members_and_places_through_the_alias() -> None:
    code = (
        "from flask import request\n\ndef f():\n    request.args.get('x')\n    x = request.args\n"
    )
    bound, found = binding(code)
    assert bound.source_for_call(found[0]) is not None
    assert bound.source_for_place(Place(base="request", steps=(".args", "[*]"))) is not None
    assert bound.source_for_place(Place(base="request", steps=(".method",))) is None


def test_a_dotted_pattern_source_matches_a_javascript_place() -> None:
    bound, _ = binding("function f(req) { return req.query.name; }\n", JS)
    assert bound.source_for_place(Place(base="req", steps=(".query", ".name"))) is not None
    assert bound.source_for_place(Place(base="req", steps=(".url",))) is None


def test_typescript_uses_the_javascript_catalogues() -> None:
    module = lower_source("function f(req: Request) { exec(req.query.x); }\n", Language.TYPESCRIPT)
    assert Binding(shipped_catalogues(), module.aliases, "typescript").sources


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_every_sink_entry_of_a_language_is_indexed(language: str) -> None:
    bound = Binding(shipped_catalogues(), (), language)
    assert bound.sinks and bound.sources and bound.sanitisers
