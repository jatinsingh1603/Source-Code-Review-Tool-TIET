"""URI resolution and region conversion (E14-02)."""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.analysis.engines.sarif.locations import (
    SourceCache,
    region_to_location,
    resolve_uri,
)
from codekavach.analysis.engines.sarif.model import ArtifactLocation, Region, Run
from tests.support.sarif import write_tree

BACKSLASH = chr(92)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    view = tmp_path / "view"
    view.mkdir()
    return view


def resolve(uri: str, root: Path, run: Run | None = None, **kwargs: object) -> str | None:
    artifact = ArtifactLocation.model_validate({"uri": uri, **kwargs})
    return resolve_uri(artifact, run or Run(), root)


def test_plain_path(root: Path) -> None:
    assert resolve("src/app.py", root) == "src/app.py"


def test_every_spelling_gives_the_same_path(root: Path) -> None:
    absolute = root.resolve().as_posix()
    spellings = [
        "src/my app.py",
        "src/my%20app.py",
        "src" + BACKSLASH + "my app.py",
        "./src/my app.py",
        "src/./x/../my app.py",
        "file:///" + absolute.lstrip("/") + "/src/my%20app.py",
        absolute + "/src/my app.py",
    ]
    assert {resolve(spelling, root) for spelling in spellings} == {"src/my app.py"}


def test_uri_base_id_indirection(root: Path) -> None:
    base = "file:///" + root.resolve().as_posix().lstrip("/") + "/"
    run = Run.model_validate({"originalUriBaseIds": {"%SRCROOT%": {"uri": base}}})
    assert resolve("src/app.py", root, run, uriBaseId="%SRCROOT%") == "src/app.py"


def test_a_chained_base_id(root: Path) -> None:
    run = Run.model_validate(
        {
            "originalUriBaseIds": {
                "OUTER": {"uri": "file:///" + root.resolve().as_posix().lstrip("/") + "/"},
                "INNER": {"uri": "pkg/", "uriBaseId": "OUTER"},
            }
        }
    )
    assert resolve("mod.py", root, run, uriBaseId="INNER") == "pkg/mod.py"


def test_an_undefined_base_id_means_the_root(root: Path) -> None:
    assert resolve("src/app.py", root, uriBaseId="%UNKNOWN%") == "src/app.py"


def test_a_foreign_absolute_base_keeps_the_relative_part(root: Path) -> None:
    run = Run.model_validate({"originalUriBaseIds": {"B": {"uri": "file:///home/ci/work/"}}})
    assert resolve("src/app.py", root, run, uriBaseId="B") == "src/app.py"


def test_artifact_index_reference(root: Path) -> None:
    run = Run.model_validate(
        {"artifacts": [{"location": {"uri": "a.py"}}, {"location": {"uri": "b/c.py"}}]}
    )
    assert resolve_uri(ArtifactLocation(index=1), run, root) == "b/c.py"
    assert resolve_uri(ArtifactLocation(index=5), run, root) is None
    assert resolve_uri(ArtifactLocation(index=-1), run, root) is None


def test_the_container_mount_point_is_the_root(root: Path) -> None:
    assert resolve("/src/app/x.py", root) == "app/x.py"
    assert resolve("file:///src/app/x.py", root) == "app/x.py"


@pytest.mark.parametrize(
    "uri",
    [
        "../../etc/passwd",
        "src/../../outside.py",
        "..",
        ".",
        "",
        "/etc/passwd",
        "file:///etc/passwd",
        "file://attacker/share/x.py",
        "http://example.invalid/x.py",
        "C:" + BACKSLASH + "Windows" + BACKSLASH + "x.py",
        "src/a" + chr(0) + "b.py",
        "%2e%2e/%2e%2e/etc/passwd",
        "src/..%2f..%2fx.py",
    ],
)
def test_a_path_that_leaves_the_root_is_rejected(uri: str, root: Path) -> None:
    assert resolve(uri, root) is None


def test_a_directory_traversal_inside_the_root_is_normalised(root: Path) -> None:
    assert resolve("a/b/../c.py", root) == "a/c.py"


@given(st.text(max_size=60))
def test_no_uri_resolves_to_a_path_outside_the_root(uri: str) -> None:
    found = resolve(uri, Path("/scan/root"))
    if found is not None:
        assert not found.startswith("/")
        assert ".." not in found.split("/")


# --- regions -----------------------------------------------------------------------------------


def test_region_with_columns() -> None:
    lines = ["alpha beta", "gamma"]
    found = region_to_location(
        Region(start_line=1, start_column=7, end_line=1, end_column=11), "a.py", lines
    )
    assert (found.start_line, found.end_line, found.start_col, found.end_col) == (1, 1, 7, 11)


def test_region_without_end_uses_the_start_line_and_line_end() -> None:
    found = region_to_location(Region(start_line=2, start_column=2), "a.py", ["abc", "defg"])
    assert (found.end_line, found.start_col, found.end_col) == (2, 2, 5)


def test_region_without_columns_has_none() -> None:
    found = region_to_location(Region(start_line=2, end_line=3), "a.py", ["a", "b", "c"])
    assert (found.start_col, found.end_col) == (None, None)


def test_a_missing_region_is_line_one() -> None:
    found = region_to_location(None, "package.json", ["{}"])
    assert (found.start_line, found.end_line, found.start_col) == (1, 1, None)


def test_the_end_line_is_clamped_to_the_file() -> None:
    assert (
        region_to_location(Region(start_line=2, end_line=99), "a.py", ["a", "b", "c"]).end_line == 3
    )


def test_a_region_after_the_end_of_the_file_is_rejected() -> None:
    with pytest.raises(ValueError, match="after the end"):
        region_to_location(Region(start_line=9), "a.py", ["a", "b"])


def test_columns_are_code_points_not_utf16_units() -> None:
    line = "\U0001f600 x = 1"  # one code point, two UTF-16 units
    kinds = {
        None: (3, 4),
        "unicodeCodePoints": (3, 4),
        "utf16CodeUnits": (2, 3),
    }
    for kind, expected in kinds.items():
        found = region_to_location(
            Region(start_line=1, start_column=3, end_line=1, end_column=4),
            "a.py",
            [line],
            column_kind=kind,
        )
        assert (found.start_col, found.end_col) == expected, kind


def test_utf16_columns_over_astral_characters_are_converted() -> None:
    line = "\U0001f600 x"  # columns in UTF-16: emoji 1-2, space 3, x 4
    found = region_to_location(
        Region(start_line=1, start_column=4, end_line=1, end_column=5),
        "a.py",
        [line],
        column_kind="utf16CodeUnits",
    )
    assert (found.start_col, found.end_col) == (3, 4)
    assert found.start_col is not None and found.end_col is not None
    assert line[found.start_col - 1 : found.end_col - 1] == "x"


def test_lines_are_split_by_the_project_rule_not_splitlines(root: Path) -> None:
    # U+2028 and form feed split lines for str.splitlines(), not for the project's line model.
    separator = chr(0x2028)
    formfeed = chr(0x0C)
    nl = chr(10)
    crlf = chr(13) + chr(10)
    text = f"one{separator}still one{nl}second{crlf}third{formfeed}still third{nl}"
    write_tree(root, {"a.py": text})
    expected = [f"one{separator}still one", "second", f"third{formfeed}still third"]
    assert SourceCache(root).lines("a.py") == expected


# --- the source cache --------------------------------------------------------------------------


def test_source_cache_reads_and_caches(root: Path) -> None:
    write_tree(root, {"a.py": "x = 1\ny = 2\n"})
    cache = SourceCache(root)
    assert cache.lines("a.py") == ["x = 1", "y = 2"]
    assert cache.head("a.py") == b"x = 1\ny = 2\n"
    assert cache.lines("missing.py") is None
    assert cache.head("missing.py") == b""


def test_source_cache_refuses_a_symlink_out_of_the_root(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    try:
        (root / "link.py").symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    assert SourceCache(root).lines("link.py") is None
