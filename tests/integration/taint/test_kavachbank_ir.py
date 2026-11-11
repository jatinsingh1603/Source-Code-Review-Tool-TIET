"""The KavachBank sample lowers completely and its source-to-sink shapes are visible (E17-01)."""

from pathlib import Path

from codekavach.analysis.taint.defuse import analyse
from codekavach.analysis.taint.ir import Call, IRModule
from codekavach.core.models import Language
from tests.support.kavachbank import FIXTURE_ROOT
from tests.support.taint import lower_source

LANGUAGES = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT}


def lowered() -> dict[str, IRModule]:
    found: dict[str, IRModule] = {}
    for path in sorted((FIXTURE_ROOT / "services").rglob("*")):
        language = LANGUAGES.get(path.suffix)
        if language is None or "node_modules" in path.parts:
            continue
        relative = path.relative_to(FIXTURE_ROOT).as_posix()
        found[relative] = lower_source(path.read_text(encoding="utf-8"), language, path=relative)
    return found


def test_every_sample_file_lowers_without_skips_and_analyses() -> None:
    modules = lowered()
    assert modules
    for path, module in modules.items():
        assert module.functions, path
        for function in module.functions:
            assert function.is_analysed, (path, function.qualname, function.skipped_reason)
            analyse(function)


def test_request_sources_and_sinks_appear_as_calls_with_resolved_symbols() -> None:
    symbols = {
        call.callee.symbol or call.callee.text
        for module in lowered().values()
        for function in module.functions
        for block in function.blocks
        for call in block.stmts
        if isinstance(call, Call)
    }
    assert any(name.endswith("execute") for name in symbols)
    assert any(name.startswith("flask.request") for name in symbols)


def test_a_handler_parameter_reaches_its_first_read() -> None:
    handlers = lowered()["services/api/handlers.py"]
    function = next(f for f in handlers.functions if f.params)
    info = analyse(function)
    assert info.parameters
    assert any(info.uses(definition) for definition in info.parameters)
    assert Path(handlers.path).suffix == ".py"
