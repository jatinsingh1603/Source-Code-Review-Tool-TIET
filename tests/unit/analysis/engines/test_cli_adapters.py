"""The command-line engine family of E15: planning rules, the cppcheck conversion, absence."""

import json
from pathlib import Path

import pytest

from codekavach.analysis.engines.adapters.brakeman import BrakemanAdapter
from codekavach.analysis.engines.adapters.cppcheck import CppcheckAdapter, report_to_sarif
from codekavach.analysis.engines.adapters.detekt import DetektAdapter
from codekavach.analysis.engines.adapters.devskim import DevskimAdapter
from codekavach.analysis.engines.adapters.flawfinder import FlawfinderAdapter
from codekavach.analysis.engines.adapters.gosec import GosecAdapter
from codekavach.analysis.engines.adapters.njsscan import NjsscanAdapter
from codekavach.analysis.engines.adapters.psalm import PsalmAdapter
from codekavach.analysis.engines.adapters.semgrep_ce import SemgrepCeAdapter
from codekavach.analysis.engines.base import EngineAdapter
from codekavach.analysis.engines.sarif.errors import SarifFormatError
from codekavach.config import Settings
from codekavach.core.models import Language
from tests.support.engines import tree_files

ADAPTERS: list[EngineAdapter] = [
    GosecAdapter(),
    FlawfinderAdapter(),
    CppcheckAdapter(),
    DetektAdapter(),
    PsalmAdapter(),
    BrakemanAdapter(),
    SemgrepCeAdapter(),
    NjsscanAdapter(),
    DevskimAdapter(),
]
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "engines"


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.id)
def test_an_absent_engine_is_reported_not_raised(
    adapter: EngineAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "")
    probe = adapter.probe(Settings())
    assert not probe.available
    assert adapter.install_hint()


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.id)
def test_no_run_is_planned_without_a_file_in_its_languages(adapter: EngineAdapter) -> None:
    assert adapter.build_invocation(Path(), [], Settings()) is None
    assert not adapter.applies_to([Language.SQL], [])


def test_psalm_is_not_planned_without_its_configuration() -> None:
    tree = FIXTURES / "psalm-taint" / "basic" / "tree"
    assert PsalmAdapter().build_invocation(tree, tree_files(tree), Settings()) is not None
    bare = FIXTURES / "brakeman" / "basic" / "tree"  # Ruby only
    assert PsalmAdapter().build_invocation(bare, tree_files(bare), Settings()) is None


def test_psalm_needs_psalm_xml_and_autoload(tmp_path: Path) -> None:
    (tmp_path / "a.php").write_text("<?php\n", encoding="utf-8")
    files = tree_files(tmp_path)
    assert PsalmAdapter().build_invocation(tmp_path, files, Settings()) is None
    (tmp_path / "psalm.xml").write_text("<psalm/>", encoding="utf-8")
    assert PsalmAdapter().build_invocation(tmp_path, files, Settings()) is None
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "autoload.php").write_text("<?php\n", encoding="utf-8")
    assert PsalmAdapter().build_invocation(tmp_path, files, Settings()) is not None


def test_brakeman_needs_a_rails_application(tmp_path: Path) -> None:
    (tmp_path / "a.rb").write_text("puts 1\n", encoding="utf-8")
    files = tree_files(tmp_path)
    assert BrakemanAdapter().build_invocation(tmp_path, files, Settings()) is None
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "application.rb").write_text("module A; end\n", encoding="utf-8")
    assert (
        BrakemanAdapter().build_invocation(tmp_path, tree_files(tmp_path), Settings()) is not None
    )


def test_semgrep_ce_is_not_planned_without_rule_paths(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    files = tree_files(tmp_path)
    assert SemgrepCeAdapter().build_invocation(tmp_path, files, Settings()) is None
    settings = Settings.model_validate({"engines": {"rule_paths": [str(tmp_path / "rules")]}})
    invocation = SemgrepCeAdapter().build_invocation(tmp_path, files, settings)
    assert invocation is not None
    assert "--metrics=off" in invocation.argv
    assert str(tmp_path / "rules") in invocation.argv


def test_cppcheck_xml_becomes_sarif() -> None:
    raw = (FIXTURES / "cppcheck" / "basic" / "output.xml").read_bytes()
    log = json.loads(report_to_sarif(raw))
    results = log["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["bufferAccessOutOfBounds", "uninitvar"]
    assert results[0]["properties"]["cwe"] == 788


@pytest.mark.parametrize(
    "raw",
    [
        b"not xml",
        b"<!DOCTYPE x [<!ENTITY a 'b'>]><results><errors/></results>",
        b"<other/>",
    ],
)
def test_cppcheck_rejects_a_bad_report(raw: bytes) -> None:
    with pytest.raises(SarifFormatError):
        report_to_sarif(raw)
