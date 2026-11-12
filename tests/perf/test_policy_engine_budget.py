"""Policy engine budgets (E25-01): 500 path rules build in 50 ms, 50,000 warm resolves in 1 s."""

import pytest

from codekavach.config import Settings
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.policy.engine import PolicyEngine, load_document
from codekavach.privacy.policy.globs import GlobMatcher
from codekavach.privacy.policy.resolve import PolicyResolver
from tests.support.perf import assert_within_budget, measure

pytestmark = pytest.mark.perf


def _document(rules: int) -> str:
    return "".join(f'[[path]]\npattern = "src/m{i}/**"\nlevel = "L4"\n' for i in range(rules))


def test_engine_with_500_path_rules_builds_within_50_ms() -> None:
    document, digest = load_document(_document(500))
    settings = Settings()
    assert_within_budget(
        measure(lambda: PolicyEngine(settings, document, digest)), 0.05, label="build"
    )


def test_50000_warm_resolves_within_one_second() -> None:
    document, digest = load_document(_document(50))
    engine = PolicyEngine(Settings(), document, digest)
    paths = [f"src/m{i % 60}/f{i % 100}.py" for i in range(1000)]
    for path in paths:
        engine.resolve(path, TrustTier.PUBLIC)

    def warm() -> None:
        for _ in range(50):
            for path in paths:
                engine.resolve(path, TrustTier.PUBLIC)

    assert_within_budget(measure(warm, repeat=2), 1.0, label="warm resolve")


def test_pathological_pattern_stays_linear() -> None:
    """``**/**/**/**/x`` against 10,000 deep paths: the glob and the settings-side never-send."""
    matcher = GlobMatcher(["**/**/**/**/x", "**/*.pem"])
    resolver = PolicyResolver(Settings())
    paths = [f"a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p{i}" for i in range(10_000)]

    def run() -> None:
        for path in paths:
            matcher.matches(path)
            resolver.is_never_send(path)

    assert_within_budget(measure(run, repeat=1), 1.0, label="pathological")
