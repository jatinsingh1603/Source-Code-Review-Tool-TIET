"""Import extraction and origin classification (E07-04)."""

import importlib.resources
from pathlib import Path
from textwrap import dedent

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import Language
from codekavach.parsing import REGISTRY, parse
from codekavach.parsing.imports import (
    MAX_CONFIG_BYTES,
    DefaultImportResolver,
    UnsupportedLanguage,
    attach_imports,
    extract_imports,
    node_builtin_names,
    python_stdlib_names,
)
from codekavach.parsing.symbols import build_symbol_table

EXTENSIONS = {
    Language.PYTHON: "py",
    Language.JAVASCRIPT: "js",
    Language.TYPESCRIPT: "ts",
    Language.JAVA: "java",
    Language.GO: "go",
}


def _raws(language: Language, source: str) -> list[tuple[str, str | None, str | None, str | None]]:
    parsed = parse(f"case.{EXTENSIONS[language]}", language, dedent(source).lstrip("\n"))
    return [(r.module, r.imported, r.alias, r.bound) for r in extract_imports(parsed)]


# --- extraction ----------------------------------------------------------------------------


def test_python_import_forms() -> None:
    assert _raws(
        Language.PYTHON,
        """
        import a.b
        import c as d
        from a.b import e as f, g
        from . import x
        from ..pkg import y
        from .mod import *
        from __future__ import annotations
        """,
    ) == [
        ("a.b", None, None, "a"),
        ("c", None, "d", "d"),
        ("a.b", "e", "f", "f"),
        ("a.b", "g", None, "g"),
        (".", "x", None, "x"),
        ("..pkg", "y", None, "y"),
        (".mod", "*", None, None),
        ("__future__", "annotations", None, None),
    ]


def test_python_dynamic_imports_with_a_literal_argument() -> None:
    assert _raws(
        Language.PYTHON,
        """
        m = __import__("lit")
        n = importlib.import_module("lit2")
        importlib.import_module(".rel", package="p")
        """,
    ) == [("lit", None, None, "m"), ("lit2", None, None, "n"), (".rel", None, None, None)]


def test_python_dynamic_imports_without_a_literal_are_ignored() -> None:
    assert (
        _raws(
            Language.PYTHON,
            """
        a = __import__(name)
        b = importlib.import_module(f"pkg.{x}")
        c = importlib.import_module(b"bytes")
        d = __import__()
        """,
        )
        == []
    )


def test_javascript_and_typescript_import_forms() -> None:
    assert _raws(
        Language.TYPESCRIPT,
        """
        import def, { a, b as c } from "m1";
        import * as ns from "m2";
        import "side-effect";
        import type { T } from "m3";
        export { q } from "m4";
        export * from "m5";
        export * as allm from "m6";
        import eq = require("m11");
        """,
    ) == [
        ("m1", "default", None, "def"),
        ("m1", "a", None, "a"),
        ("m1", "b", "c", "c"),
        ("m2", "*", None, "ns"),
        ("side-effect", None, None, None),
        ("m3", "T", None, "T"),
        ("m4", "q", None, None),
        ("m5", "*", None, None),
        ("m6", "*", None, None),
        ("m11", "*", None, "eq"),
    ]


def test_commonjs_require_and_dynamic_import_with_a_literal() -> None:
    assert _raws(
        Language.JAVASCRIPT,
        """
        const r = require("m7");
        const { s1, s2: s3 } = require("m8");
        const lazy = await import("m9");
        import("m10").then(f);
        const t = require(`m12`);
        """,
    ) == [
        ("m7", None, None, "r"),
        ("m8", "s1", None, "s1"),
        ("m8", "s2", None, "s3"),
        ("m9", None, None, "lazy"),
        ("m10", None, None, None),
        ("m12", None, None, "t"),
    ]


def test_dynamic_forms_without_a_literal_are_ignored_in_javascript() -> None:
    assert (
        _raws(
            Language.JAVASCRIPT,
            """
        const a = require(name);
        const b = import(`x${y}`);
        require();
        other("not-an-import");
        """,
        )
        == []
    )


def test_a_syntax_error_does_not_stop_extraction_of_the_rest() -> None:
    raws = _raws(Language.PYTHON, "import os\nimport (\nimport sys\n")
    assert ("os", None, None, "os") in raws


def test_languages_without_import_rules_raise_unsupported_language() -> None:
    with pytest.raises(UnsupportedLanguage):
        DefaultImportResolver(Language.DOCKERFILE)


def test_ruby_php_c_and_cpp_have_no_import_rules_and_classify_conservatively(
    tmp_path: Path,
) -> None:
    parsed = parse("a.rb", Language.RUBY, "require 'json'\n")
    assert extract_imports(parsed) == ()
    verdict = DefaultImportResolver(Language.RUBY).classify_detailed("json", project_root=tmp_path)
    assert (verdict.origin, verdict.conservative) == ("internal", True)


# --- python classification -----------------------------------------------------------------


@pytest.fixture
def python_root(tmp_path: Path) -> Path:
    (tmp_path / "billing").mkdir()
    (tmp_path / "billing" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "toplevel.py").write_text("", encoding="utf-8")
    (tmp_path / "namespace_pkg").mkdir()  # no __init__.py: a namespace package
    (tmp_path / "src" / "layout").mkdir(parents=True)
    return tmp_path


@pytest.mark.parametrize(
    ("module", "origin"),
    [
        ("billing.engine", "internal"),
        ("billing", "internal"),
        ("toplevel", "internal"),
        ("namespace_pkg.sub", "internal"),
        ("layout.mod", "internal"),
        (".", "internal"),
        ("..pkg", "internal"),
        (".helpers", "internal"),
        ("hashlib", "stdlib"),
        ("os.path", "stdlib"),
        ("__future__", "stdlib"),
        ("flask", "third_party"),
        ("numpy.linalg", "third_party"),
    ],
)
def test_python_classification(python_root: Path, module: str, origin: str) -> None:
    resolver = DefaultImportResolver(Language.PYTHON)
    assert resolver.classify(module, project_root=python_root) == origin


@pytest.mark.parametrize("module", ["", "   ", "a b", "1abc", "a..b", "a.", "x" * 600, "a\x00b"])
def test_an_unresolvable_python_module_is_internal_and_conservative(
    python_root: Path, module: str
) -> None:
    verdict = DefaultImportResolver(Language.PYTHON).classify_detailed(
        module, project_root=python_root
    )
    assert (verdict.origin, verdict.conservative) == ("internal", True)


def test_a_resolvable_module_is_not_marked_conservative(python_root: Path) -> None:
    resolver = DefaultImportResolver(Language.PYTHON)
    for module in ("billing", "hashlib", "flask", ".x"):
        assert not resolver.classify_detailed(module, project_root=python_root).conservative


def test_the_project_tree_beats_the_standard_library(python_root: Path) -> None:
    (python_root / "json").mkdir()
    assert DefaultImportResolver(Language.PYTHON).classify("json", project_root=python_root) == (
        "internal"
    )


def test_known_internal_names_cover_packages_below_the_root(tmp_path: Path) -> None:
    resolver = DefaultImportResolver(Language.PYTHON, internal_names={"service_pkg"})
    assert resolver.classify("service_pkg.x", project_root=tmp_path) == "internal"
    assert DefaultImportResolver(Language.PYTHON).classify(
        "service_pkg.x", project_root=tmp_path
    ) == ("third_party")


# --- javascript and typescript classification ---------------------------------------------


@pytest.fixture
def ts_root(tmp_path: Path) -> Path:
    (tmp_path / "tsconfig.json").write_text(
        dedent(
            """
            {
              // comments and trailing commas are legal here
              "compilerOptions": {
                "baseUrl": "src",
                /* block comment */
                "paths": { "@app/*": ["src/app/*"], "@lib": ["src/lib/index.ts"], },
              },
            }
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        '{"name": "x", "imports": {"#config": "./c.ts", "#utils/*": "./u/*.ts"}, "extra": [1]}',
        encoding="utf-8",
    )
    (tmp_path / "src" / "components").mkdir(parents=True)
    (tmp_path / "src" / "store.ts").write_text("", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("module", "origin"),
    [
        ("./util", "internal"),
        ("../up/x", "internal"),
        ("/abs/path", "internal"),
        ("@app/greet", "internal"),
        ("@app/deep/er", "internal"),
        ("@lib", "internal"),
        ("#config", "internal"),
        ("#utils/a", "internal"),
        ("components/Button", "internal"),
        ("store", "internal"),
        ("node:crypto", "stdlib"),
        ("fs", "stdlib"),
        ("fs/promises", "stdlib"),
        ("path", "stdlib"),
        ("@angular/core", "third_party"),
        ("@scope/pkg/deep/import", "third_party"),
        ("lodash", "third_party"),
        ("lodash/fp", "third_party"),
    ],
)
def test_javascript_classification(ts_root: Path, module: str, origin: str) -> None:
    resolver = DefaultImportResolver(Language.TYPESCRIPT)
    assert resolver.classify(module, project_root=ts_root) == origin


@pytest.mark.parametrize("module", ["", "@", "@scope", "has space", "a\\b", "x" * 600])
def test_an_unresolvable_javascript_specifier_is_internal_and_conservative(
    ts_root: Path, module: str
) -> None:
    verdict = DefaultImportResolver(Language.JAVASCRIPT).classify_detailed(
        module, project_root=ts_root
    )
    assert (verdict.origin, verdict.conservative) == ("internal", True)


def test_a_base_url_outside_the_project_root_is_ignored(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / "secret_pkg").mkdir(parents=True)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "tsconfig.json").write_text(
        '{"compilerOptions": {"baseUrl": "../outside"}}', encoding="utf-8"
    )
    resolver = DefaultImportResolver(Language.TYPESCRIPT)
    assert resolver.classify("secret_pkg", project_root=root) == "third_party"


def test_an_oversized_or_malformed_config_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions": {"paths": {"@big/*": []}}}' + " " * MAX_CONFIG_BYTES, encoding="utf-8"
    )
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    resolver = DefaultImportResolver(Language.TYPESCRIPT)
    assert resolver.classify("@big/thing", project_root=tmp_path) == "third_party"


def test_a_comment_marker_inside_a_string_is_not_a_comment(tmp_path: Path) -> None:
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions": {"paths": {"@u/*": ["http://x/*"]}}}', encoding="utf-8"
    )
    resolver = DefaultImportResolver(Language.TYPESCRIPT)
    assert resolver.classify("@u/a", project_root=tmp_path) == "internal"


# --- properties ----------------------------------------------------------------------------


@given(st.text(max_size=80))
def test_classification_is_total_for_arbitrary_strings(module: str) -> None:
    for language in (Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT):
        resolver = DefaultImportResolver(language)
        origin = resolver.classify(module, project_root=Path())
        assert origin in ("internal", "third_party", "stdlib")


@given(st.text(max_size=40))
def test_relative_specifiers_always_classify_internal(rest: str) -> None:
    root = Path()
    assert DefaultImportResolver(Language.PYTHON).classify("." + rest, project_root=root) == (
        "internal"
    )
    for prefix in (".", "/"):
        resolver = DefaultImportResolver(Language.JAVASCRIPT)
        assert resolver.classify(prefix + rest, project_root=root) == "internal"


# --- data files and the symbol-table API ---------------------------------------------------


@pytest.mark.parametrize("filename", ["python_stdlib.txt", "node_builtins.txt"])
def test_the_standard_library_lists_are_sorted_unique_non_empty_and_versioned(
    filename: str,
) -> None:
    text = (importlib.resources.files("codekavach.parsing.data") / filename).read_text("utf-8")
    lines = text.splitlines()
    header = [line for line in lines if line.startswith("#")]
    names = [line for line in lines if line and not line.startswith("#")]
    assert names
    assert names == sorted(names)
    assert len(names) == len(set(names))
    assert any(line.startswith("# language-version:") for line in header)
    assert any(line.startswith("# generated:") for line in header)


def test_the_loaded_lists_contain_well_known_members() -> None:
    assert {"os", "sys", "hashlib", "__future__"} <= python_stdlib_names()
    assert {"fs", "fs/promises", "crypto", "path"} <= node_builtin_names()


def test_import_origin_answers_per_name_and_scope() -> None:
    source = dedent(
        """
        from flask import request
        import hashlib
        import numpy as np
        from billing.engine import accrue

        def f():
            import json as request
            return request
        """
    ).lstrip("\n")
    parsed = parse("a.py", Language.PYTHON, source)
    table = attach_imports(
        build_symbol_table(parsed, REGISTRY.get(Language.PYTHON)),
        parsed,
        DefaultImportResolver(Language.PYTHON, internal_names={"billing"}),
        project_root=Path(),
    )
    assert table.import_origin("request", 0) == "third_party"
    assert table.import_origin("hashlib", 0) == "stdlib"
    assert table.import_origin("np", 0) == "third_party"
    assert table.import_origin("accrue", 0) == "internal"
    assert table.import_origin("request", 1) == "stdlib"
    assert table.import_origin("missing", 0) is None
    assert table.conservative_import_count == 0
    assert len(table.imports) == 5


def test_conservative_classifications_are_counted() -> None:
    parsed = parse("a.py", Language.PYTHON, 'x = __import__("a b")\n')
    table = attach_imports(
        build_symbol_table(parsed, REGISTRY.get(Language.PYTHON)),
        parsed,
        DefaultImportResolver(Language.PYTHON),
        project_root=Path(),
    )
    assert table.conservative_import_count == 1
    assert table.imports[0].origin == "internal"


# --- Java and Go (E07-05) ---------------------------------------------------------------------


def test_java_imports_are_extracted_with_module_and_bound_name() -> None:
    raws = _raws(
        Language.JAVA,
        """
        import java.util.List;
        import static java.lang.Math.max;
        import com.acme.ledger.*;
        """,
    )
    assert raws == [
        ("java.util", "List", None, "List"),
        ("java.lang.Math", "max", None, "max"),
        ("com.acme.ledger", "*", None, None),
    ]


def test_go_imports_are_extracted_with_alias_blank_and_dot_forms() -> None:
    raws = _raws(
        Language.GO,
        """
        package p
        import (
            "os"
            led "github.com/acme/ledger"
            . "strings"
            _ "embed"
            "github.com/acme/other/v3"
        )
        """,
    )
    assert raws == [
        ("os", None, None, "os"),
        ("github.com/acme/ledger", None, "led", "led"),
        ("strings", "*", None, None),
        ("embed", None, None, None),
        ("github.com/acme/other/v3", None, None, "other"),
    ]


@pytest.fixture
def java_root(tmp_path: Path) -> Path:
    (tmp_path / "src" / "main" / "java" / "com" / "acme" / "billing").mkdir(parents=True)
    return tmp_path


@pytest.mark.parametrize(
    ("module", "origin"),
    [
        ("java.util", "stdlib"),
        ("java.util.concurrent", "stdlib"),
        ("javax.crypto", "stdlib"),
        ("jdk.internal.misc", "stdlib"),
        ("com.acme.billing", "internal"),
        ("com.acme.billing.model", "third_party"),
        ("org.springframework.web", "third_party"),
        ("com.google.common.collect", "third_party"),
    ],
)
def test_java_classification(java_root: Path, module: str, origin: str) -> None:
    resolver = DefaultImportResolver(Language.JAVA)
    assert resolver.classify(module, project_root=java_root) == origin


@pytest.mark.parametrize("module", ["", "has space", "a..b", "1abc", "x/y"])
def test_an_unresolvable_java_name_is_internal_and_conservative(
    java_root: Path, module: str
) -> None:
    verdict = DefaultImportResolver(Language.JAVA).classify_detailed(module, project_root=java_root)
    assert (verdict.origin, verdict.conservative) == ("internal", True)


@pytest.fixture
def go_root(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_bytes(b"module github.com/acme/billing\n\ngo 1.22\n")
    return tmp_path


@pytest.mark.parametrize(
    ("module", "origin"),
    [
        ("fmt", "stdlib"),
        ("net/http", "stdlib"),
        ("crypto/sha256", "stdlib"),
        ("github.com/acme/billing", "internal"),
        ("github.com/acme/billing/internal/ledger", "internal"),
        ("./sibling", "internal"),
        ("github.com/acme/billing-other", "third_party"),
        ("github.com/stretchr/testify/assert", "third_party"),
        ("golang.org/x/sync/errgroup", "third_party"),
    ],
)
def test_go_classification(go_root: Path, module: str, origin: str) -> None:
    resolver = DefaultImportResolver(Language.GO)
    assert resolver.classify(module, project_root=go_root) == origin


@pytest.mark.parametrize("module", ["", "has space", "a\b", "//x", " "])
def test_an_unresolvable_go_path_is_internal_and_conservative(go_root: Path, module: str) -> None:
    verdict = DefaultImportResolver(Language.GO).classify_detailed(module, project_root=go_root)
    assert (verdict.origin, verdict.conservative) == ("internal", True)


def test_go_mod_is_optional_and_read_only_up_to_the_size_cap(tmp_path: Path) -> None:
    resolver = DefaultImportResolver(Language.GO)
    assert resolver.classify("github.com/acme/x", project_root=tmp_path) == "third_party"
    (tmp_path / "go.mod").write_bytes(b"module github.com/acme/x\n" + b"#" * (MAX_CONFIG_BYTES + 1))
    other = DefaultImportResolver(Language.GO)
    assert other.classify("github.com/acme/x", project_root=tmp_path) == "internal"


def test_go_internal_directory_names_make_a_dotless_first_element_internal(tmp_path: Path) -> None:
    resolver = DefaultImportResolver(Language.GO, internal_names={"billing"})
    assert resolver.classify("billing/ledger", project_root=tmp_path) == "internal"
    assert resolver.classify("fmt", project_root=tmp_path) == "stdlib"
