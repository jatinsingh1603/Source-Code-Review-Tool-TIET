"""Policy globs: ``**``, ``*``, ``?``, basename patterns, literal metacharacters, linear time."""

import time

import pytest

from codekavach.privacy.policy.errors import PolicyError
from codekavach.privacy.policy.globs import GlobMatcher, compile_pattern

CASES = [
    # ** at the start
    ("**/secrets/**", "secrets/a.py", True),
    ("**/secrets/**", "app/x/secrets/key.pem", True),
    ("**/secrets/**", "app/notsecrets/key.pem", False),
    # ** in the middle
    ("src/**/db.py", "src/db.py", True),
    ("src/**/db.py", "src/a/b/c/db.py", True),
    ("src/**/db.py", "lib/src/db.py", False),
    # ** at the end and a trailing /**
    ("src/payments/**", "src/payments", True),
    ("src/payments/**", "src/payments/ledger.py", True),
    ("src/payments/**", "src/payments_old/ledger.py", False),
    ("src/**", "src/a/b/c.py", True),
    # a directory pattern covers what is below it (fail-safe: rules only tighten)
    ("src/payments", "src/payments/ledger.py", True),
    # basename-only patterns match at any depth
    ("*.pem", "keys/prod/server.pem", True),
    ("*.pem", "server.pem", True),
    ("vendor", "a/vendor/lib.js", True),
    ("vendor", "a/vendored/lib.js", False),
    # * stays inside one segment, where fnmatch would cross /
    ("src/*.py", "src/app.py", True),
    ("src/*.py", "src/sub/app.py", False),
    ("src/*/app.py", "src/a/b/app.py", False),
    ("a*b", "acb", True),
    ("x/a*b", "x/a/b", False),
    # ? is one character other than /
    ("src/?.py", "src/a.py", True),
    ("src/?.py", "src/ab.py", False),
    ("src?x.py", "src/x.py", False),
    # regular-expression metacharacters are literal
    ("src/a.b", "src/axb", False),
    ("src/a.b", "src/a.b", True),
    ("lib/(x)+.py", "lib/(x)+.py", True),
    ("lib/(x)+.py", "lib/xx.py", False),
    ("cfg/[ab].toml", "cfg/a.toml", False),
    ("cfg/[ab].toml", "cfg/[ab].toml", True),
    # case-sensitive
    ("Src/**", "src/a.py", False),
]


@pytest.mark.parametrize(("pattern", "path", "expected"), CASES)
def test_glob_table(pattern: str, path: str, expected: bool) -> None:
    assert bool(compile_pattern(pattern).match(path)) is expected


def test_table_has_thirty_rows() -> None:
    assert len(CASES) >= 30


@pytest.mark.parametrize("pattern", ["/abs/**", "../x", "a/../b", "", "x" * 300, "a\\b"])
def test_bad_patterns_raise_ck_pol_004(pattern: str) -> None:
    with pytest.raises(PolicyError) as info:
        compile_pattern(pattern)
    assert info.value.code == "CK-POL-004"


def test_matcher_returns_indices_in_order() -> None:
    matcher = GlobMatcher(["src/**", "*.py", "docs/**", "src/a.py"])
    assert matcher.matches("src/a.py") == (0, 1, 3)
    assert matcher.matches("docs/x.md") == (2,)
    assert matcher.matches("other.txt") == ()


def test_pathological_pattern_is_linear() -> None:
    rx = compile_pattern("**/**/**/**/x")
    paths = ["/".join(["seg"] * (i % 40 + 1)) + "/y" for i in range(10_000)]
    start = time.perf_counter()
    assert not any(rx.match(p) for p in paths)
    assert time.perf_counter() - start < 2.0
