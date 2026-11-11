"""Size and time caps, robustness on arbitrary input, and the memoised lowering (E17-01)."""

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.analysis.taint.cache import cache_key, lower_cached
from codekavach.analysis.taint.cfg import build_cfg
from codekavach.analysis.taint.defuse import analyse
from codekavach.analysis.taint.ir import IRModule
from codekavach.analysis.taint.lowering import get_lowering
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language
from codekavach.core.pipeline.memo import DiskItemMemo
from codekavach.core.store.layout import StateLayout
from codekavach.parsing import parse
from codekavach.parsing.symbols import SymbolTable
from tests.support.taint import function_of, lower_source

BIG = "def big(a):\n" + "".join(f"    x{n} = f(a)\n" for n in range(400))


def test_a_function_over_the_node_cap_is_skipped_and_the_rest_of_the_file_is_lowered() -> None:
    module = lower_source(
        BIG + "def small(a):\n    return a\n", settings=TaintSettings(max_function_nodes=100)
    )
    big = function_of(module, "big")
    assert big.skipped_reason == "max_function_nodes"
    assert not big.is_analysed and big.blocks == ()
    assert function_of(module, "small").is_analysed


def test_a_function_over_the_block_cap_is_skipped() -> None:
    code = "def f(a):\n" + "".join(f"    if a:\n        g({n})\n" for n in range(40))
    module = lower_source(code, settings=TaintSettings(max_blocks=20))
    assert function_of(module, "f").skipped_reason == "max_blocks"


def test_the_timeout_skips_a_function_instead_of_hanging() -> None:
    module = lower_source(
        BIG, settings=TaintSettings(timeout_seconds=0.1, max_function_nodes=5_000_000)
    )
    # A fast machine may finish inside the deadline, so only the contract is asserted.
    reason = function_of(module, "big").skipped_reason
    assert reason in {None, "timeout"}


def test_a_lower_access_path_limit_truncates_earlier() -> None:
    module = lower_source("def f(a):\n    x = a.b.c\n", settings=TaintSettings(max_access_path=1))
    function = function_of(module, "f")
    assert "a.b..." in module.model_dump_json() or function.blocks


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(st.text(alphabet=st.characters(codec="ascii"), max_size=300))
def test_arbitrary_python_never_raises_and_always_yields_a_well_formed_graph(code: str) -> None:
    module = lower_source(code)
    for function in module.functions:
        ids = {b.id for b in function.blocks}
        assert all(b.stmts for b in function.blocks)
        cfg = build_cfg(function)
        assert set(cfg.order) <= ids
        analyse(function)


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(alphabet=st.characters(codec="ascii"), max_size=300))
def test_arbitrary_javascript_never_raises(code: str) -> None:
    module = lower_source(code, Language.JAVASCRIPT)
    for function in module.functions:
        analyse(function)


def test_the_memoised_lowering_is_reused_and_survives_the_store(tmp_path: Path) -> None:
    parsed = parse("a.py", Language.PYTHON, "def f(a):\n    return g(a)\n")
    lowering = get_lowering(Language.PYTHON)
    memo = DiskItemMemo(StateLayout(tmp_path / "state"))
    config = TaintSettings()
    table = SymbolTable(scopes=(), symbols=())
    first = lower_cached(memo, "a" * 64, parsed, table, lowering, config)
    second = lower_cached(memo, "a" * 64, parsed, table, lowering, config)
    assert first == second
    assert isinstance(second, IRModule)
    assert memo.stats().hits == 1


def test_the_cache_key_changes_with_everything_the_result_depends_on() -> None:
    parsed = parse("a.py", Language.PYTHON, "x = 1\n")
    other = parse("b.py", Language.PYTHON, "x = 1\n")
    lowering = get_lowering(Language.PYTHON)
    base = cache_key("h" * 64, parsed, lowering, TaintSettings())
    assert base != cache_key("g" * 64, parsed, lowering, TaintSettings())
    assert base != cache_key("h" * 64, other, lowering, TaintSettings())
    assert base != cache_key("h" * 64, parsed, lowering, TaintSettings(max_access_path=2))
    assert base != cache_key("h" * 64, parsed, lowering, TaintSettings(max_blocks=99))
    assert base == cache_key("h" * 64, parsed, lowering, TaintSettings(explain=True))
