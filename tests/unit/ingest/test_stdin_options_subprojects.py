"""``StdinSource``, ``IngestOptions`` and sub-project detection and selection (E06-03)."""

import io
from pathlib import Path

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.core.models import Language
from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.models import SourceFile
from codekavach.ingest.options import IngestOptions, OptionsError
from codekavach.ingest.sources.archive import ArchiveSource
from codekavach.ingest.sources.base import UnsupportedSource
from codekavach.ingest.sources.git import GitSource
from codekavach.ingest.sources.local import LocalPathSource
from codekavach.ingest.sources.selection import select_source
from codekavach.ingest.sources.stdin import StdinSource, check_stdin_filename
from codekavach.ingest.subprojects import (
    SubprojectSelectionError,
    detect_subprojects,
    normalise_selection,
    select_subprojects,
    subproject_of,
)
from tests.support.hostile import tar_of, zip_of


def limits(**overrides: object) -> IngestLimits:
    return IngestLimits.from_settings(IngestSettings(**overrides))  # type: ignore[arg-type]


# --- standard input ------------------------------------------------------------------------------


def test_stdin_is_written_as_one_named_file(tmp_path: Path) -> None:
    source = StdinSource(filename="hook.py", stream=io.BytesIO(b"import os\n"))
    root = source.materialise("-", limits=limits(), into=tmp_path / "w")
    assert [p.name for p in root.iterdir()] == ["hook.py"]
    assert (root / "hook.py").read_bytes() == b"import os\n"
    assert StdinSource.owns_root is True


@pytest.mark.parametrize(
    "name",
    ["../evil.py", "a/b.py", "a\\b.py", "..", ".", "x..py", "C:evil.py", "a\x00b.py", "", " a.py"],
)
def test_a_stdin_filename_that_is_not_a_bare_name_is_refused(tmp_path: Path, name: str) -> None:
    source = StdinSource(filename=name or None, stream=io.BytesIO(b"x"))
    with pytest.raises(UnsupportedSource):
        source.materialise("-", limits=limits(), into=tmp_path / "w")
    assert not (tmp_path / "w").exists()


def test_a_missing_stdin_filename_is_refused() -> None:
    with pytest.raises(UnsupportedSource, match="stdin-filename"):
        check_stdin_filename(None)


def test_input_over_the_per_file_cap_is_refused_and_nothing_is_written(tmp_path: Path) -> None:
    source = StdinSource(filename="big.py", stream=io.BytesIO(b"x" * 101))
    with pytest.raises(LimitExceededError) as raised:
        source.materialise("-", limits=limits(max_file_size_bytes=100), into=tmp_path / "w")
    assert raised.value.kind is LimitKind.FILE_SIZE
    assert not (tmp_path / "w").exists()


def test_input_of_exactly_the_cap_is_accepted(tmp_path: Path) -> None:
    source = StdinSource(filename="ok.py", stream=io.BytesIO(b"x" * 100))
    root = source.materialise("-", limits=limits(max_file_size_bytes=100), into=tmp_path / "w")
    assert (root / "ok.py").stat().st_size == 100


def test_the_stdin_source_only_serves_the_dash(tmp_path: Path) -> None:
    source = StdinSource(filename="a.py", stream=io.BytesIO(b"x"))
    with pytest.raises(UnsupportedSource):
        source.materialise("somewhere", limits=limits(), into=tmp_path / "w")


# --- dispatch ------------------------------------------------------------------------------------


def test_select_source_dispatches_by_target(tmp_path: Path) -> None:
    (tmp_path / "plain.py").write_text("x", encoding="utf-8")
    archive = zip_of(tmp_path / "a.zip", {"a.py": "x"})
    tarball = tar_of(tmp_path / "a.tar.gz", {"a.py": "x"}, "w:gz")
    assert isinstance(select_source(str(tmp_path)), LocalPathSource)
    assert isinstance(select_source(str(tmp_path / "plain.py")), LocalPathSource)
    assert isinstance(select_source(str(archive)), ArchiveSource)
    assert isinstance(select_source(str(tarball)), ArchiveSource)
    assert isinstance(select_source("https://git.example.invalid/x"), GitSource)
    assert isinstance(select_source("ssh://git@git.example.invalid/x"), GitSource)
    assert isinstance(select_source("git@git.example.invalid:x/y"), GitSource)
    assert isinstance(select_source("https://git.example.invalid/x.git"), GitSource)
    assert isinstance(select_source("elsewhere/missing.git"), GitSource)
    assert isinstance(select_source("-", IngestOptions(stdin_filename="a.py")), StdinSource)


def test_a_bare_repository_directory_is_cloned_not_scanned_in_place(tmp_path: Path) -> None:
    bare = tmp_path / "app.git"
    (bare / "objects").mkdir(parents=True)
    (bare / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    assert isinstance(select_source(str(bare)), GitSource)
    plain = tmp_path / "plain.git"
    plain.mkdir()
    assert isinstance(select_source(str(plain)), LocalPathSource)


def test_a_directory_named_like_an_archive_is_still_a_directory(tmp_path: Path) -> None:
    folder = tmp_path / "looks-like.zip"
    folder.mkdir()
    assert isinstance(select_source(str(folder)), LocalPathSource)


def test_the_options_reach_the_git_source() -> None:
    source = select_source(
        "https://git.example.invalid/x.git", IngestOptions(ref="v1", depth=3, diff_since="v0")
    )
    assert isinstance(source, GitSource)
    with pytest.raises(UnsupportedSource):
        select_source("https://git.example.invalid/x.git", IngestOptions(ref="--evil"))


# --- options -------------------------------------------------------------------------------------


def test_the_defaults_have_an_empty_mapping_and_round_trip() -> None:
    assert IngestOptions().to_mapping() == {}
    assert IngestOptions.from_mapping(None) == IngestOptions()
    assert IngestOptions.from_mapping({}) == IngestOptions()


def test_options_round_trip_through_the_mapping() -> None:
    options = IngestOptions(
        ref="v1",
        depth=4,
        git_credential="env:T",
        stdin_filename="a.py",
        diff_since="main",
        include_deleted=True,
        subprojects=("a", "b/c"),
    )
    assert IngestOptions.from_mapping(options.to_mapping()) == options


@pytest.mark.parametrize(
    "raw",
    [
        "text",
        {"unknown": 1},
        {"ref": 5},
        {"depth": 0},
        {"depth": True},
        {"depth": 2_000_000},
        {"include_deleted": "yes"},
        {"subprojects": "a"},
        {"subprojects": [1]},
        {"ref": "x" * 5000},
    ],
)
def test_a_malformed_options_mapping_is_refused_without_echoing_values(raw: object) -> None:
    with pytest.raises(OptionsError) as raised:
        IngestOptions.from_mapping(raw)
    assert "xxxx" not in str(raised.value)


# --- sub-projects --------------------------------------------------------------------------------


def source_file(path: str, *, vendored: bool = False) -> SourceFile:
    return SourceFile(
        path=path,
        sha256="0" * 64,
        size_bytes=1,
        language=Language.UNKNOWN,
        line_count=1,
        encoding="utf-8",
        is_vendored=vendored,
    )


def files_of(*paths: str) -> list[SourceFile]:
    return [source_file(p) for p in paths]


def test_a_root_manifest_and_two_nested_ones_give_three_subprojects() -> None:
    files = files_of(
        "pyproject.toml",
        "src/app.py",
        "web/package.json",
        "web/src/index.js",
        "admin/package.json",
        "admin/main.js",
    )
    found = detect_subprojects(Path(), files)
    assert [(s.path, s.kind, s.manifest) for s in found] == [
        (".", "python", "pyproject.toml"),
        ("admin", "node", "admin/package.json"),
        ("web", "node", "web/package.json"),
    ]


@pytest.mark.parametrize(
    ("manifest", "kind"),
    [
        ("pyproject.toml", "python"),
        ("setup.py", "python"),
        ("package.json", "node"),
        ("pom.xml", "java-maven"),
        ("build.gradle", "java-gradle"),
        ("build.gradle.kts", "java-gradle"),
        ("go.mod", "go"),
        ("composer.json", "php"),
        ("App.csproj", "dotnet"),
        ("Gemfile", "ruby"),
    ],
)
def test_every_manifest_name_gives_its_kind(manifest: str, kind: str) -> None:
    (found,) = detect_subprojects(Path(), files_of(f"svc/{manifest}"))
    assert (found.path, found.kind, found.manifest) == ("svc", kind, f"svc/{manifest}")


def test_a_directory_with_several_manifests_is_one_subproject_of_the_first_kind() -> None:
    found = detect_subprojects(Path(), files_of("setup.py", "package.json", "pyproject.toml"))
    assert [(s.kind, s.manifest) for s in found] == [("python", "pyproject.toml")]


def test_vendored_manifests_and_lookalikes_are_not_subprojects() -> None:
    files = [
        source_file("node_modules/left-pad/package.json", vendored=True),
        source_file("docs/package.json.md"),
        source_file(".csproj"),
        source_file("notes/Gemfile.lock"),
    ]
    assert detect_subprojects(Path(), files) == ()


def test_the_nearest_enclosing_subproject_wins() -> None:
    found = detect_subprojects(
        Path(), files_of("pyproject.toml", "web/package.json", "web/ui/package.json")
    )
    assert subproject_of("web/ui/a.js", found).path == "web/ui"  # type: ignore[union-attr]
    assert subproject_of("web/a.js", found).path == "web"  # type: ignore[union-attr]
    assert subproject_of("README.md", found).path == "."  # type: ignore[union-attr]
    assert subproject_of("webby/a.js", found).path == "."  # type: ignore[union-attr]
    assert subproject_of("x.py", []) is None


def test_selecting_a_subproject_keeps_the_files_below_it() -> None:
    files = files_of("a/x.py", "a/sub/y.py", "ab/z.py", "b/w.py")
    kept = select_subprojects(files, ["a"])
    assert [f.path for f in kept] == ["a/x.py", "a/sub/y.py"]
    assert [f.path for f in select_subprojects(files, ["a", "b/"])] == [
        "a/x.py",
        "a/sub/y.py",
        "b/w.py",
    ]
    assert len(select_subprojects(files, ["."])) == 4


def test_a_selection_that_matches_nothing_is_an_error_not_an_empty_scan() -> None:
    with pytest.raises(SubprojectSelectionError):
        select_subprojects(files_of("a/x.py"), ["a", "nope"])


@pytest.mark.parametrize("raw", ["/abs", "../up", "a/../b", "a\\b", "", "a\x00"])
def test_a_malformed_selection_is_refused(raw: str) -> None:
    with pytest.raises(SubprojectSelectionError):
        normalise_selection(raw)


@pytest.mark.parametrize(
    ("raw", "expected"), [("a/b/", "a/b"), ("./a", "a"), (".", "."), ("a//b", "a/b")]
)
def test_a_selection_is_normalised(raw: str, expected: str) -> None:
    assert normalise_selection(raw) == expected
