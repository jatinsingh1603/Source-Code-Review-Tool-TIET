import importlib.util
import shutil
import sys
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
TODAY = date(2026, 9, 27)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("new_adr", REPO_ROOT / "tools/dev/new_adr.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["new_adr"] = module
    spec.loader.exec_module(module)
    return module


new_adr = _load()

HEADER = (
    "# Index\n\n"
    "| Number | Title | Status | Date | Supersedes | Issue |\n"
    "|--------|-------|--------|------|------------|-------|\n"
)


RESERVED_ROWS = (
    "| 0001 | Technology stack | Reserved | | | #21 (E01-10) |\n"
    "| 0002 | External engines as subprocesses | Reserved | | | #22 (E01-11) |\n"
    "| 0003 | Single egress | Reserved | | | #23 (E01-12) |\n"
    "| 0004 | Changelog and versioning | Reserved | | | #33 (E01-22) |\n"
    "| 0005 | Logging and no-telemetry | Reserved | | | #24 (E01-13) |\n"
)


@pytest.fixture
def adr_dir(tmp_path: Path) -> Path:
    """An ADR directory with the real template and five reserved numbers, independent of
    which records the repository has accepted since."""
    target = tmp_path / "adr"
    target.mkdir()
    shutil.copy(REPO_ROOT / "docs/adr/0000-template.md", target)
    (target / "README.md").write_text(HEADER + RESERVED_ROWS, encoding="utf-8")
    return target


def _empty_dir(tmp_path: Path, rows: str = "") -> Path:
    target = tmp_path / "empty"
    target.mkdir()
    shutil.copy(REPO_ROOT / "docs/adr/0000-template.md", target)
    (target / "README.md").write_text(HEADER + rows, encoding="utf-8")
    return target


# next number


def test_next_number_with_no_records(tmp_path: Path) -> None:
    assert new_adr.next_number(_empty_dir(tmp_path)) == 1


def test_next_number_with_gaps(tmp_path: Path) -> None:
    d = _empty_dir(tmp_path)
    (d / "0001-a.md").write_text("x", encoding="utf-8")
    (d / "0007-b.md").write_text("x", encoding="utf-8")
    assert new_adr.next_number(d) == 8


def test_next_number_counts_reserved_rows(adr_dir: Path) -> None:
    assert new_adr.next_number(adr_dir) == 6


# slugs


@pytest.mark.parametrize(
    ("title", "slug"),
    [
        ("Technology stack", "technology-stack"),
        ("Logging and no-telemetry!", "logging-and-no-telemetry"),
        ("  Many   spaces   here ", "many-spaces-here"),
        ("Café naïve résumé", "cafe-naive-resume"),
        ("Use C++/Rust (maybe?)", "use-c-rust-maybe"),
    ],
)
def test_slugify(title: str, slug: str) -> None:
    assert new_adr.slugify(title) == slug


def test_slugify_limits_length_at_word_boundary() -> None:
    slug = new_adr.slugify("word " * 30)
    assert len(slug) <= 60
    assert not slug.endswith("-")
    assert slug.startswith("word-word")


# creation


def test_created_file_is_filled(adr_dir: Path) -> None:
    path = new_adr.create_adr("Example decision", adr_dir, TODAY)
    assert path.name == "0006-example-decision.md"
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# ADR-0006: Example decision\n")
    assert "| Date | 2026-09-27 |" in text
    assert "| Status | Proposed |" in text
    assert "NNNN" not in text
    assert "YYYY-MM-DD" not in text


def test_index_gains_exactly_one_row(adr_dir: Path) -> None:
    before = (adr_dir / "README.md").read_text(encoding="utf-8").splitlines()
    new_adr.create_adr("Example decision", adr_dir, TODAY)
    after = (adr_dir / "README.md").read_text(encoding="utf-8").splitlines()
    assert len(after) == len(before) + 1
    added = [line for line in after if line not in before]
    assert added == [
        "| [0006](0006-example-decision.md) | Example decision | Proposed | 2026-09-27 | | |"
    ]
    assert all(line in after for line in before)


def test_reserved_title_reuses_number(adr_dir: Path) -> None:
    path = new_adr.create_adr("technology STACK", adr_dir, TODAY)
    assert path.name == "0001-technology-stack.md"
    rows = {r.number: r for r in new_adr.parse_index(adr_dir / "README.md")}
    assert rows[1].status == "Proposed"
    assert rows[2].status == "Reserved"
    assert "#21 (E01-10)" in (adr_dir / "README.md").read_text(encoding="utf-8")


def test_refuses_to_overwrite(adr_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    new_adr.create_adr("Example decision", adr_dir, TODAY)
    with pytest.raises(new_adr.AdrError):
        new_adr.create_adr("Example decision", adr_dir, TODAY)
    new_adr.create_adr("Technology stack", adr_dir, TODAY)
    code = new_adr.main(["Technology stack", "--adr-dir", str(adr_dir)])
    assert code == 1
    assert "already exists" in capsys.readouterr().err


# check_index


def test_check_index_is_clean_for_repository() -> None:
    assert new_adr.check_index(REPO_ROOT / "docs/adr") == []


def test_check_index_is_clean_after_creation(adr_dir: Path) -> None:
    new_adr.create_adr("Example decision", adr_dir, TODAY)
    new_adr.create_adr("Single egress", adr_dir, TODAY)
    assert new_adr.check_index(adr_dir) == []


def test_check_index_reports_file_without_row(adr_dir: Path) -> None:
    new_adr.create_adr("Example decision", adr_dir, TODAY)
    index = adr_dir / "README.md"
    lines = [ln for ln in index.read_text(encoding="utf-8").splitlines() if "0006" not in ln]
    index.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("0006-example-decision.md: no index row" in p for p in new_adr.check_index(adr_dir))


def test_check_index_reports_row_without_file(adr_dir: Path) -> None:
    path = new_adr.create_adr("Example decision", adr_dir, TODAY)
    path.unlink()
    assert any("index row has no file" in p for p in new_adr.check_index(adr_dir))


def test_check_index_reports_status_mismatch(adr_dir: Path) -> None:
    path = new_adr.create_adr("Example decision", adr_dir, TODAY)
    path.write_text(
        path.read_text(encoding="utf-8").replace("| Status | Proposed |", "| Status | Accepted |"),
        encoding="utf-8",
    )
    problems = new_adr.check_index(adr_dir)
    assert any("0006-example-decision.md: status" in p for p in problems)


def test_check_index_reports_duplicate_number(adr_dir: Path) -> None:
    index = adr_dir / "README.md"
    index.write_text(
        index.read_text(encoding="utf-8") + "| 0002 | Something else | Reserved | | | |\n",
        encoding="utf-8",
    )
    assert any(
        "ADR-0002: number appears in 2 index rows" in p for p in new_adr.check_index(adr_dir)
    )


def test_check_flag_exit_codes(adr_dir: Path) -> None:
    assert new_adr.main(["--check", "--adr-dir", str(adr_dir)]) == 0
    path = new_adr.create_adr("Example decision", adr_dir, TODAY)
    path.unlink()
    assert new_adr.main(["--check", "--adr-dir", str(adr_dir)]) == 1
