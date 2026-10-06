"""The pipeline documentation is executed and compared with the code (E04-33).

``docs/reference/pipeline.md`` and ``docs/reference/writing-a-stage.md`` are references that stage
authors will copy from, so their code runs here and their tables are checked against the objects
they describe:

- every fenced block whose info string is ``python test`` is executed, one namespace per document
  (a module object, so classes defined in a block have a real ``__module__``), and every
  ``test_*`` function the blocks define is called afterwards;
- the worked example of the guide is copied into a fake distribution, discovered by the registry,
  validated with ``describe_stage`` and run inside ``run_scan``;
- the tables of events, stage metadata and categories, manifest and checkpoint fields, settings
  and error types are compared with ``EVENT_TYPES``, ``StageInfo``, ``CATEGORY_DEFAULTS``, the two
  models, ``Settings`` and the ``PipelineError`` hierarchy.
"""

import dataclasses
import importlib
import json
import pkgutil
import re
import sys
import tomllib
import types
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from codekavach.config import Settings, load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.errors import PipelineError
from codekavach.core.pipeline.events import EVENT_TYPES
from codekavach.core.pipeline.manifest import ScanManifest
from codekavach.core.pipeline.resume import Checkpoint
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import (
    CATEGORY_DEFAULTS,
    FailurePolicy,
    StageCategory,
    StageInfo,
    describe_stage,
)
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.support.pipeline import write_fake_distribution

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs" / "reference"
PIPELINE = REFERENCE / "pipeline.md"
GUIDE = REFERENCE / "writing-a-stage.md"
PAGES = (PIPELINE, GUIDE)
OPENING = re.compile(r"^```python test\s*$")
FILE_COMMENT = re.compile(r"^# file: (?P<name>[A-Za-z_][A-Za-z0-9_]*\.py)\s*$")
ABSOLUTE = re.compile(r"\b(never|guarantees?|ensures?|impossible)\b|100%", re.IGNORECASE)
ENFORCED_BY = re.compile(r"E\d{2}-\d{2}|#\d+|\btest_\w+|ADR-\d{4}|tests/")
BASE_EVENT_FIELDS = {"scan_id", "at", "seq"}


@dataclass(frozen=True)
class Block:
    page: Path
    line: int
    source: str


def python_blocks(page: Path) -> list[Block]:
    """The ``python test`` blocks of ``page`` in order."""
    lines = page.read_text(encoding="utf-8").splitlines()
    blocks: list[Block] = []
    index = 0
    while index < len(lines):
        if OPENING.match(lines[index]):
            start = index + 1
            index += 1
            body: list[str] = []
            while index < len(lines) and lines[index].rstrip() != "```":
                body.append(lines[index])
                index += 1
            blocks.append(Block(page, start + 1, "\n".join(body) + "\n"))
        index += 1
    return blocks


def toml_blocks(page: Path) -> list[str]:
    text = page.read_text(encoding="utf-8")
    return re.findall(r"^```toml\n(.*?)^```", text, flags=re.MULTILINE | re.DOTALL)


def tables(page: Path) -> list[list[list[str]]]:
    """Every Markdown table of ``page`` as rows of cells (the separator row is dropped)."""
    found: list[list[list[str]]] = []
    current: list[list[str]] = []
    for line in page.read_text(encoding="utf-8").splitlines():
        if line.startswith("|"):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if all(set(cell) <= set("-: ") for cell in cells):
                continue
            current.append(cells)
        elif current:
            found.append(current)
            current = []
    if current:
        found.append(current)
    return found


def bare(cell: str) -> str:
    return cell.replace("`", "").strip()


def table_with_header(page: Path, *header: str) -> list[list[str]]:
    """The body rows of the table whose header cells (without backticks) are ``header``."""
    for table in tables(page):
        if [bare(cell) for cell in table[0]] == list(header):
            return table[1:]
    raise AssertionError(f"{page.name} has no table with the header {header}")


def names_in(cell: str) -> set[str]:
    return set(re.findall(r"`([^`]+)`", cell))


# --- the code blocks ---------------------------------------------------------------------------


def run_page(page: Path) -> list[str]:
    """Execute the blocks of ``page`` in one module; return the ``test_*`` functions it ran."""
    name = f"docs_{page.stem.replace('-', '_')}"
    module = types.ModuleType(name)
    sys.modules[name] = module
    try:
        for block in python_blocks(page):
            code = compile(block.source, f"{page.name}:{block.line}", "exec")
            exec(code, module.__dict__)  # noqa: S102 - the point of this test
        ran = []
        for key, value in list(module.__dict__.items()):
            if key.startswith("test_") and callable(value):
                value()
                ran.append(key)
        return ran
    finally:
        del sys.modules[name]


def test_the_two_pages_have_executable_blocks() -> None:
    counts = {page.name: len(python_blocks(page)) for page in PAGES}
    assert all(count >= 1 for count in counts.values()), counts
    assert sum(counts.values()) >= 6, counts


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_every_block_runs(page: Path) -> None:
    run_page(page)


def test_the_guide_defines_and_runs_tests_of_its_own() -> None:
    assert run_page(GUIDE) == [
        "test_analyse_todo_reports_the_todo_lines",
        "test_a_missing_file_is_a_warning_not_a_failure",
    ]


def test_a_failing_block_is_reported(tmp_path: Path) -> None:
    page = tmp_path / "broken.md"
    page.write_text("```python test\nassert 1 == 2\n```\n", encoding="utf-8")
    with pytest.raises(AssertionError):
        run_page(page)


def test_other_fences_are_not_executed(tmp_path: Path) -> None:
    page = tmp_path / "plain.md"
    page.write_text("```python\nraise SystemExit(1)\n```\n```python test\nx = 1\n```\n", "utf-8")
    assert [block.source for block in python_blocks(page)] == ["x = 1\n"]


# --- the worked example in a fake distribution --------------------------------------------------


def worked_example() -> tuple[str, str, dict[str, str]]:
    """The module block of the guide, its file name and the entry points of its TOML block."""
    for block in python_blocks(GUIDE):
        first = block.source.splitlines()[0]
        match = FILE_COMMENT.match(first)
        if match:
            example = (block.source, match["name"])
            break
    else:
        raise AssertionError("the guide has no block that starts with '# file: <name>.py'")
    entry_points: dict[str, str] = {}
    for text in toml_blocks(GUIDE):
        document = tomllib.loads(text)
        found = document.get("project", {}).get("entry-points", {}).get("codekavach.stages")
        if found:
            entry_points = dict(found)
    assert entry_points, "the guide has no entry-point block"
    return example[0], example[1], entry_points


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "a.py").write_text("x = 1\n# TODO: handle errors\ny = 2\n", encoding="utf-8")
    return root


def install_example(site: Path) -> PluginRegistry:
    source, filename, entry_points = worked_example()
    write_fake_distribution(
        site,
        "ck-todo",
        "0.1.0",
        entry_points={"codekavach.stages": entry_points},
        modules={filename: source},
    )
    write_fake_distribution(
        site,
        "ck-fake-stages",
        "1.0",
        entry_points={"codekavach.stages": {"ingest": "tests.support.fake_stages_module:ingest"}},
        modules={},
    )
    return PluginRegistry(
        [spec for spec in discover() if spec.dist_name in {"ck-todo", "ck-fake-stages"}]
    )


def test_the_example_is_discovered_and_passes_describe_stage(fake_site: Path) -> None:
    registry = install_example(fake_site)
    assert "ck_todo" not in sys.modules  # discovery reads metadata only
    stage = registry.stages()["analyse-todo"]
    info = describe_stage(stage)
    assert info.category is StageCategory.ANALYSE
    assert info.failure_policy is FailurePolicy.DEGRADE
    assert info.cacheable and not info.salt_dependent
    assert info.requires == {"files"} and info.provides == {"candidates.raw"}
    registered = registry.stage_infos()["analyse-todo"]
    assert registered.origin == "ck-todo==0.1.0"
    assert registry.failures() == ()


def test_the_example_runs_inside_run_scan_and_produces_a_part(fake_site: Path, repo: Path) -> None:
    registry = install_example(fake_site)
    config = load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})
    outcome = run_scan(config, str(repo), salt=ScanSalt.from_hex("5a" * 32), registry=registry)
    assert outcome.result.status is ScanStatus.COMPLETED
    module = importlib.import_module("ck_todo")
    reader = OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)
    parts = reader.get_parts("candidates.raw", module.TodoCandidate)
    assert parts == {"analyse-todo": [module.TodoCandidate(path="a.py", line=2)]}


def test_the_example_is_a_cache_hit_when_nothing_changed(fake_site: Path, repo: Path) -> None:
    registry = install_example(fake_site)
    config = load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})
    salt = ScanSalt.from_hex("5a" * 32)
    run_scan(config, str(repo), salt=salt, registry=registry)
    second = run_scan(config, str(repo), salt=salt, registry=registry)
    outcomes = {run.stage: run.outcome.value for run in second.result.stage_runs}
    assert outcomes["analyse-todo"] == "cached"
    assert outcomes["ingest"] == "succeeded"  # ingest is never cached


# --- the tables against the code ---------------------------------------------------------------


def test_the_events_table_matches_event_types() -> None:
    rows = table_with_header(PIPELINE, "Event", "kind", "Fields")
    documented = {bare(row[1]): (bare(row[0]), names_in(row[2])) for row in rows}
    assert set(documented) == set(EVENT_TYPES)
    for kind, (class_name, fields) in documented.items():
        cls = EVENT_TYPES[kind]
        assert cls.__name__ == class_name
        own = {field.name for field in dataclasses.fields(cls)} - BASE_EVENT_FIELDS
        assert fields == own, kind


def test_the_metadata_table_lists_every_stage_info_field() -> None:
    rows = table_with_header(PIPELINE, "Attribute", "Default", "Meaning")
    documented = [bare(row[0]) for row in rows]
    assert len(documented) == len(set(documented))
    assert set(documented) == {field.name for field in dataclasses.fields(StageInfo)}


def test_the_category_table_matches_the_defaults() -> None:
    rows = table_with_header(PIPELINE, "Category", "Failure policy", "Cacheable", "Salt dependent")
    expected = {
        (None if bare(row[0]) == "(none)" else StageCategory(bare(row[0]))): (
            FailurePolicy(bare(row[1])),
            bare(row[2]) == "yes",
            bare(row[3]) == "yes",
        )
        for row in rows
    }
    assert expected == dict(CATEGORY_DEFAULTS)


def test_the_manifest_and_checkpoint_tables_cover_their_models() -> None:
    tables_with_fields = [
        table[1:]
        for table in tables(PIPELINE)
        if [bare(c) for c in table[0]] == ["Field", "Meaning"]
    ]
    documented: dict[str, set[str]] = {}
    for rows in tables_with_fields:
        names = set().union(*(names_in(row[0]) for row in rows))
        if "schema_version" in names:
            documented["manifest"] = names
        elif "target_digest" in names:
            documented["checkpoint"] = names
    assert documented["manifest"] == set(ScanManifest.model_fields)
    assert documented["checkpoint"] == set(Checkpoint.model_fields)


REQUIRED_SETTINGS = (
    "scan.stage_timeout_seconds",
    "scan.stage_timeouts",
    "scan.cache_max_size_mb",
    "scan.cache_keep_scans",
    "plugins.allow_distributions",
    "plugins.disable",
)


def test_every_settings_key_of_the_pipeline_is_documented_with_its_default() -> None:
    rows = table_with_header(PIPELINE, "Key", "Default", "Range", "Meaning")
    documented = {bare(row[0]): row for row in rows}
    assert set(REQUIRED_SETTINGS) <= set(documented)
    values = Settings().model_dump(mode="json")
    for key in REQUIRED_SETTINGS:
        node = values
        for part in key.split("."):
            node = node[part]
        assert json.loads(bare(documented[key][1])) == node, key
        assert documented[key][3].strip(), f"{key} has no meaning"


def pipeline_errors() -> set[str]:
    from codekavach import core  # noqa: PLC0415

    for module in pkgutil.walk_packages(core.__path__, "codekavach.core."):
        importlib.import_module(module.name)
    found: set[str] = set()

    def walk(cls: type[PipelineError]) -> None:
        found.add(cls.__name__)
        for child in cls.__subclasses__():
            walk(child)

    walk(PipelineError)
    return found


def test_the_error_table_lists_every_pipeline_error() -> None:
    rows = table_with_header(PIPELINE, "Exception", "Raised when")
    documented = {bare(row[0]) for row in rows}
    assert documented == pipeline_errors()


def test_the_scenario_codes_are_codes_the_code_uses() -> None:
    text = (ROOT / "src" / "codekavach" / "core" / "pipeline" / "orchestrator.py").read_text(
        encoding="utf-8"
    ) + (ROOT / "src" / "codekavach" / "core" / "pipeline" / "policy.py").read_text(
        encoding="utf-8"
    )
    rows = table_with_header(PIPELINE, "Scenario", "Stage outcome and code", "Effect on the run")
    for row in rows:
        for code in re.findall(r"`([a-z_]+)`", row[1]):
            if code in {"failed", "skipped", "cancelled", "timed_out"}:
                continue
            assert f'"{code}"' in text, f"{code} is documented but not used"


# --- the wording and the links -----------------------------------------------------------------


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_absolute_words_name_what_enforces_them(page: Path) -> None:
    offenders = [
        f"{page.name}:{number}: {line.strip()[:80]}"
        for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), start=1)
        if ABSOLUTE.search(line) and not ENFORCED_BY.search(line)
    ]
    assert offenders == []


def links(page: Path) -> Iterator[tuple[str, Path]]:
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", page.read_text(encoding="utf-8")):
        if "://" not in target:
            yield target, (page.parent / target).resolve()


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_relative_links_resolve(page: Path) -> None:
    broken = [target for target, path in links(page) if not path.exists()]
    assert broken == []


def test_the_pages_link_each_other_and_the_architecture_points_to_both() -> None:
    assert "(writing-a-stage.md)" in PIPELINE.read_text(encoding="utf-8")
    assert "(pipeline.md)" in GUIDE.read_text(encoding="utf-8")
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "docs/reference/pipeline.md" in architecture
    assert "docs/reference/writing-a-stage.md" in architecture


def test_the_database_page_explains_how_to_inspect_it() -> None:
    text = (REFERENCE / "database.md").read_text(encoding="utf-8")
    assert "sqlite3 -readonly" in text
    assert "confidential" in text


def test_the_guide_has_the_ten_item_checklist() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    section = text.split("## Checklist", 1)[1].split("\n## ", 1)[0]
    items = re.findall(r"^\d+\. ", section, flags=re.MULTILINE)
    assert len(items) == 10
