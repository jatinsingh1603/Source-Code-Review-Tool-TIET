"""``detect_language``: the corpus, each resolution step in isolation and purity (E06-02)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import Language
from codekavach.ingest import langdetect
from codekavach.ingest.langdetect import (
    EXTENSION_MAP,
    FILENAME_MAP,
    MODELINE_MAP,
    SHEBANG_MAP,
    detect_language,
    disambiguate,
)

PY, JS, TS = Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT
SH, UNKNOWN = Language.SHELL, Language.UNKNOWN

# (path, head, expected). One row per case; the ids are the paths and the first bytes.
CORPUS: list[tuple[str, bytes, Language]] = [
    # Python
    ("services/api/accounts.py", b"from flask import Flask\n", PY),
    ("stubs/app.pyi", b"def f() -> int: ...\n", PY),
    ("gui.pyw", b"import tkinter\n", PY),
    ("scripts/run", b"#!/usr/bin/env python3\nprint(1)\n", PY),
    ("scripts/run2", b"#!/usr/bin/python3.11 -u\n", PY),
    ("tool", b"# -*- mode: python -*-\nx = 1\n", PY),
    # JavaScript
    ("web/app.js", b"const x = 1;\n", JS),
    ("web/App.jsx", b"export default () => <div/>;\n", JS),
    ("lib/index.mjs", b"export const a = 1;\n", JS),
    ("lib/index.cjs", b"module.exports = {};\n", JS),
    ("lib/flow.js", b"// @flow\nconst x: number = 1;\n", JS),
    ("bin/cli", b"#!/usr/bin/env node\nconsole.log(1)\n", JS),
    ("bin/cli2", b"#!/usr/bin/env -S node --no-warnings\n", JS),
    # TypeScript
    ("web/app.ts", b"const x: number = 1;\n", TS),
    ("web/App.tsx", b"export const A = () => <div/>;\n", TS),
    ("lib/mod.mts", b"export {};\n", TS),
    ("lib/mod.cts", b"export {};\n", TS),
    ("lib/utf8.ts", "const s = 'é';\n".encode(), TS),
    # Java, Kotlin
    ("src/Main.java", b"class Main {}\n", Language.JAVA),
    ("src/App.kt", b"fun main() {}\n", Language.KOTLIN),
    ("build.gradle.kts", b"plugins { }\n", Language.KOTLIN),
    # C and C++
    ("src/main.c", b"int main(void) { return 0; }\n", Language.C),
    ("include/engine.h", b"#define X 1\nstruct s { int a; };\n", Language.C),
    ("include/engine_kb.h", b"namespace kb {\nint f();\n}\n", Language.CPP),
    ("include/vec.h", b"template <class T> struct V {};\n", Language.CPP),
    ("include/str.h", b"#include <string>\nstd::string f();\n", Language.CPP),
    ("include/cls.h", b"class Foo {\n};\n", Language.CPP),
    (
        "include/comment.h",
        b"/* class is a word here */\n// namespace too\nint f(void);\n",
        Language.C,
    ),
    ("src/a.cc", b"int f() { return 1; }\n", Language.CPP),
    ("src/a.cpp", b"int f() { return 1; }\n", Language.CPP),
    ("src/a.cxx", b"int f() { return 1; }\n", Language.CPP),
    ("src/a.hpp", b"#pragma once\n", Language.CPP),
    ("src/a.hh", b"#pragma once\n", Language.CPP),
    # PHP
    ("public/index.php", b"<?php echo 1;\n", Language.PHP),
    ("view.phtml", b"<h1><?= $x ?></h1>\n", Language.PHP),
    ("cgi/page", b"<?php\nphpinfo();\n", Language.PHP),
    # Go, C#, Ruby
    ("cmd/main.go", b"package main\n", Language.GO),
    ("Program.cs", b"class P {}\n", Language.CSHARP),
    ("app/models/user.rb", b"class User; end\n", Language.RUBY),
    ("Gemfile", b"source 'https://rubygems.org'\n", Language.RUBY),
    ("Rakefile", b"task :default\n", Language.RUBY),
    ("tasks/build.rake", b"task :b\n", Language.RUBY),
    ("bin/rails_cmd", b"#!/usr/bin/env ruby\n", Language.RUBY),
    # Shell
    ("scripts/deploy", b"#!/usr/bin/env bash\n", SH),
    ("scripts/build.sh", b"echo hi\n", SH),
    ("scripts/z.zsh", b"echo hi\n", SH),
    ("scripts/legacy", b"#!/bin/sh\n", SH),
    ("scripts/vimmed", b"# vim: set ft=sh:\n", SH),
    # Configuration and data formats
    ("Dockerfile", b"FROM python:3.12\n", Language.DOCKERFILE),
    ("Dockerfile.prod", b"FROM python:3.12\n", Language.DOCKERFILE),
    ("build/app.dockerfile", b"FROM scratch\n", Language.DOCKERFILE),
    ("infra/main.tf", b'resource "x" "y" {}\n', Language.TERRAFORM),
    ("ci/config.yml", b"a: 1\n", Language.YAML),
    ("ci/config.yaml", b"a: 1\n", Language.YAML),
    (".gitlab-ci.yml", b"stages: [test]\n", Language.YAML),
    ("package.json", b'{"name": "x"}\n', Language.JSON),
    ("pyproject.toml", b"[project]\n", Language.TOML),
    ("Pipfile", b"[packages]\n", Language.TOML),
    ("pom.xml", b"<project/>\n", Language.XML),
    ("data/feed", b'<?xml version="1.0"?>\n<a/>\n', Language.XML),
    ("data/schema", b"<!DOCTYPE note SYSTEM 'n.dtd'>\n", Language.XML),
    ("db/schema.sql", b"CREATE TABLE t (a int);\n", Language.SQL),
    ("db/pg.sql", b"CREATE FUNCTION f() RETURNS int AS $$ $$;\n", Language.SQL),
    ("site/index.html", b"<html></html>\n", Language.HTML),
    ("site/index.htm", b"<html></html>\n", Language.HTML),
    ("site/page", b"<!DOCTYPE html>\n<html></html>\n", Language.HTML),
    # Recognised but no language member: UNKNOWN, never a guess
    ("README.md", b"# Title\n<?php echo 1; ?>\n", UNKNOWN),
    ("notes.txt", b"#!/bin/bash\n", UNKNOWN),
    ("legacy.m", b"function y = f(x)\n", UNKNOWN),
    ("legacy_objc.m", b"@interface A : NSObject\n@end\n", UNKNOWN),
    ("tools/script.pl", b"#!/usr/bin/perl\nprint 1;\n", UNKNOWN),
    ("Makefile", b"all:\n\techo hi\n", UNKNOWN),
    ("GNUmakefile", b"#!/bin/sh\n", UNKNOWN),
    # Nothing to go on
    ("LICENSE", b"MIT License\n", UNKNOWN),
    ("data/blob", b"\x89PNG\r\n", UNKNOWN),
    ("empty", b"", UNKNOWN),
    # Binary look-alike: a transport stream shares the .ts extension
    ("video/clip.ts", b"\x47\x40\x00\x10\x00\x00\xb0\x0d" + b"\x00" * 40, UNKNOWN),
    # Qt translation file: text with an XML declaration under the .ts extension
    ("i18n/app_de.ts", b'<?xml version="1.0"?>\n<!DOCTYPE TS>\n<TS/>\n', Language.XML),
    # Windows separators and a byte-order mark do not change the answer
    ("src\\win\\main.py", b"x = 1\n", PY),
    ("bom.sh", b"\xef\xbb\xbfecho hi\n", SH),
    ("bom_extensionless", b"\xef\xbb\xbf#!/bin/bash\n", SH),
]


def _case_id(case: tuple[str, bytes, Language]) -> str:
    return f"{case[0]}|{case[1][:16]!r}"


def test_corpus_has_at_least_sixty_cases_covering_every_target_language() -> None:
    assert len(CORPUS) >= 60
    targets = {
        Language.PYTHON,
        Language.JAVASCRIPT,
        Language.TYPESCRIPT,
        Language.JAVA,
        Language.KOTLIN,
        Language.C,
        Language.CPP,
        Language.PHP,
        Language.GO,
        Language.CSHARP,
        Language.RUBY,
        Language.JSON,
        Language.YAML,
        Language.TOML,
        Language.XML,
        Language.HTML,
        Language.DOCKERFILE,
        Language.SHELL,
    }
    assert targets <= {expected for _, _, expected in CORPUS}


@pytest.mark.parametrize("case", CORPUS, ids=_case_id)
def test_detection_corpus(case: tuple[str, bytes, Language]) -> None:
    path, head, expected = case
    assert detect_language(path, head) is expected


# --- the documented order, each step in isolation -------------------------------------------


def test_file_name_beats_extension() -> None:
    # ``Gemfile.lock`` is not special, but ``Dockerfile.py`` hits the prefix rule first.
    assert detect_language("Dockerfile.py", b"x = 1\n") is Language.DOCKERFILE


def test_extension_beats_shebang() -> None:
    assert detect_language("tool.py", b"#!/bin/bash\necho hi\n") is PY


def test_shebang_decides_when_there_is_no_extension() -> None:
    assert detect_language("tool", b"#!/bin/bash\necho hi\n") is SH


def test_shebang_beats_modeline() -> None:
    assert detect_language("tool", b"#!/bin/bash\n# vim: set ft=ruby:\n") is SH


def test_modeline_decides_when_the_shebang_is_unknown() -> None:
    assert detect_language("tool", b"#!/usr/bin/unknown\n# vim: set ft=ruby:\n") is Language.RUBY


def test_emacs_modeline_forms() -> None:
    assert detect_language("a", b"# -*- mode: ruby -*-\n") is Language.RUBY
    assert detect_language("a", b"# -*- python -*-\n") is PY
    assert detect_language("a", b"# -*- coding: utf-8; mode: python -*-\n") is PY


def test_modeline_beats_content_heuristic() -> None:
    assert detect_language("a", b"<?php\n// vim: set ft=ruby:\n") is Language.RUBY


def test_content_heuristic_is_last() -> None:
    assert detect_language("a", b"<?php echo 1;") is Language.PHP
    assert detect_language("a", b"plain words\n") is UNKNOWN


def test_modeline_is_only_read_near_the_top() -> None:
    head = b"\n" * 10 + b"# vim: set ft=ruby:\n"
    assert detect_language("a", head) is UNKNOWN


def test_unknown_extension_falls_through_to_the_later_steps() -> None:
    assert detect_language("script.weird", b"#!/bin/bash\n") is SH


def test_a_name_with_only_the_dockerfile_prefix_is_not_a_dockerfile() -> None:
    assert detect_language("Dockerfile.", b"x\n") is UNKNOWN


# --- tables ---------------------------------------------------------------------------------


def test_every_table_entry_names_a_real_member_and_the_keys_are_normalised() -> None:
    for table in (EXTENSION_MAP, FILENAME_MAP, SHEBANG_MAP, MODELINE_MAP):
        assert all(isinstance(value, Language) for value in table.values())
    assert all(key.startswith(".") and key == key.lower() for key in EXTENSION_MAP)
    assert not set(EXTENSION_MAP) & langdetect.UNANALYSED_EXTENSIONS
    assert Language.UNKNOWN not in EXTENSION_MAP.values()
    assert Language.UNKNOWN not in SHEBANG_MAP.values()


def test_the_tables_are_read_only() -> None:
    with pytest.raises(TypeError):
        EXTENSION_MAP[".zzz"] = PY  # type: ignore[index]


# --- ambiguous extensions -------------------------------------------------------------------


def test_disambiguate_h_by_cpp_markers_in_code_not_in_comments() -> None:
    both = (Language.C, Language.CPP)
    assert disambiguate("a.h", b"namespace n {}", both) is Language.CPP
    assert disambiguate("a.h", b"// namespace n\nint f(void);", both) is Language.C
    assert disambiguate("a.h", b"", both) is Language.C


def test_disambiguate_ts_by_text_decodability() -> None:
    candidates = (TS, Language.XML)
    assert disambiguate("a.ts", b"let x = 1;", candidates) is TS
    assert disambiguate("a.ts", b"\x47\x00\x00", candidates) is UNKNOWN
    assert disambiguate("a.ts", b"\xff\xfe\xfa", candidates) is UNKNOWN


def test_disambiguate_accepts_a_head_cut_in_the_middle_of_a_character() -> None:
    text = "const s = 'é';".encode()
    assert disambiguate("a.ts", text[:-2], (TS, Language.XML)) is TS


def test_disambiguate_never_returns_a_language_outside_the_candidates() -> None:
    assert disambiguate("a.h", b"namespace n {}", (Language.C,)) is UNKNOWN
    assert disambiguate("a.txt", b"x", (PY,)) is UNKNOWN


# --- purity ---------------------------------------------------------------------------------


@given(path=st.text(max_size=80), head=st.binary(max_size=300))
def test_detect_language_never_raises_and_is_deterministic(path: str, head: bytes) -> None:
    first = detect_language(path, head)
    assert isinstance(first, Language)
    assert detect_language(path, head) is first


def test_bytes_beyond_the_head_limit_are_ignored() -> None:
    padding = b" " * langdetect.HEAD_LIMIT
    assert detect_language("a.h", padding + b"namespace n {}") is Language.C
    assert detect_language("a.h", b"namespace n {}" + padding) is Language.CPP
