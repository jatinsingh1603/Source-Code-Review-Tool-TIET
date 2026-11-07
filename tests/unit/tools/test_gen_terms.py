"""``tools/gen_terms.py``: the terms file is generated from the manifest and checked for drift."""

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

from codekavach.config.domain_terms import parse_terms
from tests.support.kavachbank import FIXTURE_ROOT, TERMS_PATH, load_manifest, terms_for

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_terms", REPO_ROOT / "tools" / "gen_terms.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_terms"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def copy(tmp_path: Path) -> Path:
    target = tmp_path / "kavachbank"
    shutil.copytree(FIXTURE_ROOT, target)
    return target / "ground-truth"


def test_the_committed_terms_file_is_current(tool: ModuleType) -> None:
    assert tool.main(["--check"]) == 0
    assert TERMS_PATH.read_text(encoding="utf-8") == tool.render()


def test_the_output_is_the_format_the_config_layer_reads(tool: ModuleType) -> None:
    terms = parse_terms(tool.render())
    assert terms == terms_for(load_manifest())
    assert all(2 <= len(term) <= 128 for term in terms)  # E05-18 limits


def test_the_output_is_deterministic_and_carries_no_timestamp(tool: ModuleType) -> None:
    assert tool.render() == tool.render()
    assert "20" not in tool.HEADER.replace("tools/gen_terms.py", "")


def test_write_then_check_round_trips(tool: ModuleType, copy: Path) -> None:
    out, manifest = copy / "terms.txt", copy / "manifest.yaml"
    out.unlink()
    assert tool.main(["--check", "--out", str(out), "--manifest", str(manifest)]) == 2
    assert tool.main(["--out", str(out), "--manifest", str(manifest)]) == 0
    assert tool.main(["--check", "--out", str(out), "--manifest", str(manifest)]) == 0


def test_a_manifest_change_without_regeneration_fails_the_check(
    tool: ModuleType, copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = copy / "manifest.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "  - festival bonus\n", "  - festival boost\n"
        ),
        encoding="utf-8",
    )
    arguments = ["--check", "--out", str(copy / "terms.txt"), "--manifest", str(manifest)]
    assert tool.main(arguments) == 1
    error = capsys.readouterr().err
    assert "-festival bonus" in error and "+festival boost" in error and "stale" in error


def test_a_hand_edit_of_the_terms_file_fails_the_check(tool: ModuleType, copy: Path) -> None:
    out = copy / "terms.txt"
    out.write_text(out.read_text(encoding="utf-8") + "an extra term\n", encoding="utf-8")
    assert tool.main(["--check", "--out", str(out), "--manifest", str(copy / "manifest.yaml")]) == 1


def test_a_broken_manifest_is_reported_not_raised(
    tool: ModuleType, copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = copy / "manifest.yaml"
    manifest.write_text("schema_version: 9\n", encoding="utf-8")
    assert tool.main(["--check", "--manifest", str(manifest)]) == 2
    assert "gen_terms:" in capsys.readouterr().err
