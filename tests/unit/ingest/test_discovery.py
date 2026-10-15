"""``discover`` and ``build_inventory`` (E06-01)."""

import tempfile
from pathlib import Path

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.config.models.root import Settings
from codekavach.core.models import Language, split_lines
from codekavach.ingest.discovery import DiscoveryReport, build_inventory, discover
from codekavach.ingest.limits import LimitExceededError, LimitKind, SkipReason
from codekavach.ingest.models import SourceFile
from tests.support.synthetic import make_hostile_tree, make_tree


def _settings(**ingest_overrides: object) -> Settings:
    return Settings(ingest=IngestSettings(**ingest_overrides))  # type: ignore[arg-type]


def test_discover_returns_sorted_source_files() -> None:
    root = make_tree({"b.py": "y = 2\n", "a.py": "x = 1\n"})
    files = discover(root, _settings())
    assert [f.path for f in files] == ["a.py", "b.py"]


def test_discover_excludes_node_modules_and_git_by_default() -> None:
    root = make_tree(
        {
            "app.py": "x = 1\n",
            "node_modules/pkg/index.js": "var x = 1;\n",
            ".git/config": "binary-ish",
        }
    )
    files = discover(root, _settings())
    assert [f.path for f in files] == ["app.py"]


def test_discover_skips_binary_files() -> None:
    root = make_tree({"a.py": "x = 1\n", "a.bin": b"\x00\x01\x02"})
    files = discover(root, _settings())
    assert [f.path for f in files] == ["a.py"]


def test_discover_skips_files_over_the_size_limit() -> None:
    root = make_tree({"small.py": "x = 1\n", "big.py": "y = 2\n"})
    files = discover(root, _settings(max_file_size_bytes=3))
    assert [f.path for f in files] == []


def test_discover_raises_limit_exceeded_for_too_many_files() -> None:
    root = make_tree({f"f{i}.py": "x = 1\n" for i in range(5)})
    with pytest.raises(LimitExceededError) as excinfo:
        discover(root, _settings(max_files=3))
    assert excinfo.value.kind == LimitKind.FILE_COUNT
    assert str(excinfo.value.budget) in str(excinfo.value)


def test_discover_raises_limit_exceeded_for_total_bytes() -> None:
    root = make_tree({f"f{i}.py": "x" * 100 + "\n" for i in range(5)})
    with pytest.raises(LimitExceededError) as excinfo:
        discover(root, _settings(max_total_bytes=50))
    assert excinfo.value.kind == LimitKind.TOTAL_BYTES


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a\nb\nc\n", 3),
        ("a\nb\nc", 3),
        ("a\r\nb\r\n", 2),
        ("a\rb\n", 1),  # a lone \r does not terminate a line
        ("", 0),
    ],
)
def test_line_count_matches_split_lines(text: str, expected: int) -> None:
    root = make_tree({"a.txt": text})
    files = discover(root, _settings())
    assert len(files) == 1  # even an empty file is a legitimate, discoverable file
    assert files[0].line_count == expected == len(split_lines(text))


def test_discover_is_deterministic_across_runs() -> None:
    root = make_tree({f"f{i}.py": f"x = {i}\n" for i in range(20)})
    first = discover(root, _settings())
    second = discover(root, _settings())
    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]


def test_build_inventory_sorts_languages_by_descending_line_count() -> None:
    root = make_tree({"a.py": "x = 1\ny = 2\n", "b.py": "z = 3\n"})
    files = discover(root, _settings())
    inventory = build_inventory(files)
    assert inventory.total_files == 2
    assert inventory.total_lines == 3
    # Both files are Language.UNKNOWN until E06-02; one entry, the sum of both line counts.
    assert inventory.languages == ((Language.UNKNOWN, 3),)


def test_hostile_tree_walk_completes_and_writes_nothing_outside_the_root() -> None:
    root = make_hostile_tree()
    files = discover(root, _settings(max_file_size_bytes=1_000_000))
    paths = {f.path for f in files}
    assert "normal.py" in paths
    assert "huge.bin" not in paths  # too_large
    assert "invalid.txt" not in paths  # undecodable
    for source_file in files:
        assert ".." not in source_file.path.split("/")


def test_discovery_report_counts_skip_reasons() -> None:
    report = DiscoveryReport()
    report.record(SkipReason.BINARY)
    report.record(SkipReason.IGNORED)
    report.record(SkipReason.IGNORED)
    assert report.skipped == {SkipReason.BINARY: 1, SkipReason.IGNORED: 2}


def _source_file(path: str, language: Language, line_count: int) -> SourceFile:
    return SourceFile(
        path=path,
        sha256="a" * 64,
        size_bytes=10,
        language=language,
        line_count=line_count,
        encoding="utf-8",
    )


def test_build_inventory_sorts_by_line_count_then_breaks_ties_by_enum_value() -> None:
    # discover() cannot produce more than one language until E06-02 (language detection is out
    # of this issue's scope), so the tie-break itself is tested directly against SourceFile,
    # not through a discovery run.
    files = [
        _source_file("a.go", Language.GO, 5),
        _source_file("b.py", Language.PYTHON, 10),
        _source_file("c.js", Language.JAVASCRIPT, 10),  # ties PYTHON on line count
    ]
    inventory = build_inventory(files)
    # PYTHON ties JAVASCRIPT at 10 lines; "javascript" < "python" by enum value, so it sorts first.
    assert inventory.languages == (
        (Language.JAVASCRIPT, 10),
        (Language.PYTHON, 10),
        (Language.GO, 5),
    )


def _can_create_symlinks() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "target").mkdir()
        try:
            (root / "link").symlink_to(root / "target", target_is_directory=True)
        except OSError:
            return False
        return True


@pytest.mark.skipif(not _can_create_symlinks(), reason="symbolic links are not permitted here")
def test_symlink_pointing_outside_the_root_is_skipped() -> None:
    root = make_tree({"a.py": "x = 1\n"})
    outside = make_tree({"secret.py": "z = 1\n"})
    (root / "escape").symlink_to(outside, target_is_directory=True)
    files = discover(root, _settings())
    assert [f.path for f in files] == ["a.py"]


@pytest.mark.skipif(not _can_create_symlinks(), reason="symbolic links are not permitted here")
def test_symlink_loop_does_not_hang_the_walk() -> None:
    root = make_tree({"a.py": "x = 1\n"})
    loop_dir = root / "loopy"
    loop_dir.mkdir()
    (loop_dir / "self").symlink_to(loop_dir, target_is_directory=True)
    files = discover(root, _settings())  # must return, not hang
    assert [f.path for f in files] == ["a.py"]
