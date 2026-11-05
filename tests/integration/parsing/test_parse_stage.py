"""``run_scan`` with the real ``ingest`` and ``parse`` stages (E07-04)."""

from pathlib import Path

import pytest

from codekavach.config import load_settings
from codekavach.core.models import Language, ScanStatus
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.ingest.models import SourceFile
from codekavach.parsing import stage as stage_module
from codekavach.parsing.callgraph import CallGraph
from codekavach.parsing.stage import LAZY_AST_CACHE_SIZE, LazyAst, ParseStage
from codekavach.parsing.symbols import SymbolsArtefact
from tests.support.ingest import SALT_HEX, materialise_project, stages_registry
from tests.support.pipeline import CollectingBus


def scan(repo: Path, bus: CollectingBus | None = None) -> ScanOutcome:
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})
    return run_scan(
        loaded,
        str(repo),
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=stages_registry("ingest", "parse"),
        bus=bus,
    )


def store_of(outcome: ScanOutcome) -> OnDiskArtefactStore:
    return OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)


@pytest.fixture
def python_repo(tmp_path: Path) -> Path:
    return materialise_project("python_app", tmp_path / "repo")


@pytest.fixture
def ts_repo(tmp_path: Path) -> Path:
    return materialise_project("ts_app", tmp_path / "repo")


def test_the_stage_declares_its_contract() -> None:
    info = stages_registry("ingest", "parse").stage_infos()["parse"]
    assert info.requires == frozenset({keys.FILES})
    assert info.provides == frozenset({keys.AST, keys.SYMBOLS, keys.CALL_GRAPH})
    assert ParseStage.transient_provides == frozenset({keys.AST})


def test_a_python_project_is_parsed_and_its_imports_classified(python_repo: Path) -> None:
    outcome = scan(python_repo)
    assert outcome.scan.status is ScanStatus.COMPLETED
    assert {run.stage: run.outcome for run in outcome.result.stage_runs} == {
        "ingest": StageOutcome.SUCCEEDED,
        "parse": StageOutcome.SUCCEEDED,
    }
    symbols = store_of(outcome).get(keys.SYMBOLS, SymbolsArtefact)
    assert symbols.skipped == {}
    origins = {ref.module: ref.origin for ref in symbols.tables["src/app/main.py"].imports}
    assert origins == {
        "hashlib": "stdlib",
        "numpy": "third_party",
        "billing.engine": "internal",
        "flask": "third_party",
        ".": "internal",
    }


def test_the_call_graph_is_persisted_and_joins_files(python_repo: Path) -> None:
    graph = store_of(scan(python_repo)).get(keys.CALL_GRAPH, CallGraph)
    assert graph.callees("app.main.handle") == (
        "?undefined_thing",
        "app.helpers.log",
        "billing.engine.accrue",
        "hashlib.sha256",
        "numpy.zeros",
    )
    assert graph.callees("billing.engine.accrue") == ("billing.engine._scale",)


def test_a_typescript_project_uses_tsconfig_paths_and_node_prefixes(ts_repo: Path) -> None:
    bus = CollectingBus()
    outcome = scan(ts_repo, bus)
    symbols = store_of(outcome).get(keys.SYMBOLS, SymbolsArtefact)
    origins = {ref.module: ref.origin for ref in symbols.tables["src/main.ts"].imports}
    assert origins == {
        "@angular/core": "third_party",
        "@app/greet": "internal",
        "node:crypto": "stdlib",
        "./util": "internal",
    }
    # Config files are listed as not analysed, without being reported as failures.
    assert symbols.skipped == {
        "package.json": "no_language_spec",
        "tsconfig.json": "no_language_spec",
    }
    assert bus.of("warning") == []


def test_the_ast_artefact_is_never_written_to_disk(python_repo: Path) -> None:
    outcome = scan(python_repo)
    stored = set(store_of(outcome).keys())
    assert keys.AST not in stored
    assert {keys.SYMBOLS, keys.CALL_GRAPH} <= stored
    on_disk = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in outcome.state_dir.rglob("*")
        if path.is_file()
    )
    assert "undefined_thing" in on_disk  # the call graph is stored...
    assert "sha256()" not in on_disk  # ...source text is not


def test_a_second_scan_is_served_from_the_memo(python_repo: Path) -> None:
    first = scan(python_repo)
    second = scan(python_repo)
    assert (first.result.memo_hits, first.result.memo_misses) == (0, 5)
    assert (second.result.memo_hits, second.result.memo_misses) == (5, 0)
    assert store_of(first).get(keys.CALL_GRAPH, CallGraph) == store_of(second).get(
        keys.CALL_GRAPH, CallGraph
    )


def test_only_the_changed_file_is_reparsed(python_repo: Path) -> None:
    scan(python_repo)
    helpers = python_repo / "src" / "app" / "helpers.py"
    helpers.write_text(helpers.read_text(encoding="utf-8") + "\n\ndef extra():\n    return 1\n")
    again = scan(python_repo)
    # helpers changed; the others hit unless the resolver fingerprint moved (it did not).
    assert (again.result.memo_hits, again.result.memo_misses) == (4, 1)


def test_a_pack_version_bump_invalidates_every_entry(
    python_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan(python_repo)
    monkeypatch.setattr(stage_module, "pack_version", lambda: "9.9.9")
    bumped = scan(python_repo)
    assert (bumped.result.memo_hits, bumped.result.memo_misses) == (0, 5)


def test_a_parser_module_version_bump_invalidates_every_entry(
    python_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan(python_repo)
    monkeypatch.setattr(stage_module, "PARSER_MODULE_VERSION", "next")
    assert scan(python_repo).result.memo_misses == 5


def test_a_new_top_level_package_changes_other_files_import_origins(python_repo: Path) -> None:
    """Import origins depend on the project, so a cached verdict must not outlive its inputs."""
    before = store_of(scan(python_repo)).get(keys.SYMBOLS, SymbolsArtefact)
    assert {r.module: r.origin for r in before.tables["src/app/main.py"].imports}["flask"] == (
        "third_party"
    )
    (python_repo / "flask").mkdir()
    (python_repo / "flask" / "__init__.py").write_text("", encoding="utf-8")
    after = store_of(scan(python_repo)).get(keys.SYMBOLS, SymbolsArtefact)
    assert {r.module: r.origin for r in after.tables["src/app/main.py"].imports}["flask"] == (
        "internal"
    )


def test_a_file_that_is_mostly_syntax_errors_is_skipped_with_a_reason(python_repo: Path) -> None:
    garbage = "function f() { return 1; }\nconst x = () => {};\n" * 20  # JavaScript read as Python
    (python_repo / "broken.py").write_text(garbage, encoding="utf-8")
    bus = CollectingBus()
    outcome = scan(python_repo, bus)
    assert outcome.scan.status is ScanStatus.COMPLETED
    symbols = store_of(outcome).get(keys.SYMBOLS, SymbolsArtefact)
    assert symbols.skipped == {"broken.py": "too_many_errors"}
    assert "broken.py" not in symbols.tables
    assert [e.to_dict().get("code") for e in bus.of("warning")] == ["files_skipped"]


def test_a_file_whose_grammar_is_unavailable_is_skipped_and_the_stage_succeeds(
    python_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(stage_module, "grammar_available", lambda language: False)
    bus = CollectingBus()
    outcome = scan(python_repo, bus)
    assert outcome.scan.status is ScanStatus.COMPLETED
    assert {run.stage: run.outcome for run in outcome.result.stage_runs}["parse"] is (
        StageOutcome.SUCCEEDED
    )
    symbols = store_of(outcome).get(keys.SYMBOLS, SymbolsArtefact)
    assert symbols.tables == {}
    assert set(symbols.skipped.values()) == {"grammar_unavailable"}
    assert len(symbols.skipped) == 5
    assert [e.to_dict().get("code") for e in bus.of("warning")] == ["files_skipped"]


def test_a_file_over_the_size_limit_is_skipped_with_a_reason(python_repo: Path) -> None:
    (python_repo / "big.py").write_text("x = 1\n" * 400_000, encoding="utf-8")
    outcome = scan(python_repo)
    symbols = store_of(outcome).get(keys.SYMBOLS, SymbolsArtefact)
    assert symbols.skipped.get("big.py") == "too_large"
    assert outcome.scan.status is ScanStatus.COMPLETED


def test_a_file_that_vanishes_after_discovery_is_skipped_as_unreadable(
    python_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = stage_module._read

    def vanish(root: Path, file: SourceFile) -> str:
        if file.path.endswith("helpers.py"):
            (root / file.path).unlink()
        return original(root, file)

    monkeypatch.setattr(stage_module, "_read", vanish)
    symbols = store_of(scan(python_repo)).get(keys.SYMBOLS, SymbolsArtefact)
    assert symbols.skipped == {"src/app/helpers.py": "unreadable"}


def test_progress_and_failure_events_carry_no_paths_or_names(python_repo: Path) -> None:
    garbage = "function f() { return 1; }\nconst x = () => {};\n" * 20
    (python_repo / "secret_module_name.py").write_text(garbage, encoding="utf-8")
    bus = CollectingBus()
    scan(python_repo, bus)
    for event in bus.events:
        text = str(event.to_dict())
        assert "secret_module_name" not in text
        assert "undefined_thing" not in text


def test_lazy_ast_parses_on_demand_and_keeps_a_bounded_cache(python_repo: Path) -> None:
    outcome = scan(python_repo)
    files = {f.path: f for f in store_of(outcome).get_list(keys.FILES, SourceFile)}
    loaded = load_settings(target=python_repo, env={})
    lazy = LazyAst(python_repo, files, loaded.settings.parsing)
    assert len(lazy) == len(files)
    assert list(lazy) == sorted(files)
    assert lazy["src/billing/engine.py"].language.value == "python"
    assert lazy["src/billing/engine.py"] is lazy["src/billing/engine.py"]
    with pytest.raises(KeyError):
        lazy["not/a/file.py"]
    assert LAZY_AST_CACHE_SIZE >= 1
    assert len(lazy._cache) <= LAZY_AST_CACHE_SIZE


def test_lazy_ast_evicts_the_oldest_entry(tmp_path: Path) -> None:
    root = tmp_path / "many"
    root.mkdir()
    files = {}
    for index in range(LAZY_AST_CACHE_SIZE + 3):
        name = f"m{index}.py"
        (root / name).write_text(f"x{index} = {index}\n", encoding="utf-8")
        files[name] = SourceFile(
            path=name,
            language=Language.PYTHON,
            sha256="0" * 64,
            size_bytes=10,
            line_count=1,
            encoding="utf-8",
        )
    loaded = load_settings(target=root, env={})
    lazy = LazyAst(root, files, loaded.settings.parsing)
    for name in files:
        lazy[name]
    assert len(lazy._cache) == LAZY_AST_CACHE_SIZE
    assert "m0.py" not in lazy._cache
    assert lazy["m0.py"] is not None
