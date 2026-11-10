"""``safe_extract`` and ``ArchiveSource``: names, links, members, budgets and clean-up (E06-03)."""

import os
import stat
import tarfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.config.models.ingest import IngestSettings
from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.sources import archive as archive_module
from codekavach.ingest.sources import workdir as workdir_module
from codekavach.ingest.sources.archive import (
    CHUNK_BYTES,
    ArchiveSource,
    entry_parts,
    is_archive_name,
    link_escapes,
    safe_extract,
)
from codekavach.ingest.sources.base import UnsafeArchiveEntry, UnsupportedSource
from tests.support.hostile import (
    all_files,
    many_entries_tar,
    member,
    tar_gz_bomb,
    tar_of,
    tar_with_members,
    tree_size,
    zip_bomb,
    zip_of,
    zip_with_symlink,
)


def limits(**overrides: object) -> IngestLimits:
    return IngestLimits.from_settings(IngestSettings(**overrides))  # type: ignore[arg-type]


FILES = {"src/app.py": "print(1)\n", "README.md": "# hi\n", "src/pkg/mod.py": "x = 2\n"}


# --- entry names -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("/etc/passwd", "absolute"),
        ("//server/share/x", "absolute"),
        ("../../etc/passwd", "traversal"),
        ("a/../../b", "traversal"),
        ("a/b/../c", "traversal"),
        ("..", "traversal"),
        ("a\x00b", "nul"),
        ("C:/Windows/x", "drive_letter"),
        ("c:x", "drive_letter"),
        ("a/C:", "colon"),
        ("a/file.txt:stream", "colon"),
        ("a\\b", "backslash"),
        ("..\\..\\x", "backslash"),
        ("a" * 5000, "overlong"),
        ("", "empty"),
    ],
)
def test_an_unsafe_entry_name_is_rejected_with_its_rule(name: str, reason: str) -> None:
    with pytest.raises(UnsafeArchiveEntry) as raised:
        entry_parts(name, limits())
    assert raised.value.reason == reason
    assert name[:6] not in str(raised.value) or reason == "empty"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("a/b.py", ("a", "b.py")),
        ("./a/b.py", ("a", "b.py")),
        ("a//b.py", ("a", "b.py")),
        ("dir/", ("dir",)),
        ("./", ()),
        (".hidden/.x", (".hidden", ".x")),
    ],
)
def test_a_safe_entry_name_is_normalised(name: str, expected: tuple[str, ...]) -> None:
    assert entry_parts(name, limits()) == expected


@pytest.mark.parametrize(
    ("entry", "target", "relative", "escapes"),
    [
        (("a", "link"), "/etc", True, True),
        (("a", "link"), "../../x", True, True),
        (("a", "link"), "..", True, False),
        (("a", "b", "link"), "../../x", True, False),
        (("a", "link"), "sibling.txt", True, False),
        (("a", "link"), "C:\\x", True, True),
        (("a", "link"), "x\\y", True, True),
        (("a", "link"), "", True, True),
        (("a", "link"), "b/c", False, False),
        (("a", "link"), "../x", False, True),
    ],
)
def test_a_link_target_that_leaves_the_root_is_an_escape(
    entry: tuple[str, ...], target: str, relative: bool, escapes: bool
) -> None:
    assert link_escapes(entry, target, relative_to_entry=relative) is escapes


@pytest.mark.parametrize(
    ("name", "expected"),
    [("a.zip", True), ("A.TAR.GZ", True), ("a.tgz", True), ("a.txz", True), ("a.rar", False)],
)
def test_archive_names_are_recognised_by_extension(name: str, expected: bool) -> None:
    assert is_archive_name(name) is expected


# --- the supported formats -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "mode"),
    [
        ("a.tar", "w"),
        ("a.tar.gz", "w:gz"),
        ("a.tgz", "w:gz"),
        ("a.tar.bz2", "w:bz2"),
        ("a.tar.xz", "w:xz"),
    ],
)
def test_every_tar_flavour_is_extracted(tmp_path: Path, name: str, mode: str) -> None:
    archive = tar_of(tmp_path / name, FILES, mode)
    root = safe_extract(archive, tmp_path / "out", limits())
    assert all_files(root) == sorted(FILES)
    assert (root / "src" / "app.py").read_text(encoding="utf-8") == "print(1)\n"


def test_a_zip_is_extracted(tmp_path: Path) -> None:
    archive = zip_of(tmp_path / "a.zip", FILES)
    root = safe_extract(archive, tmp_path / "out", limits())
    assert all_files(root) == sorted(FILES)


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_extracted_files_are_private_and_not_executable(tmp_path: Path) -> None:
    root = safe_extract(zip_of(tmp_path / "a.zip", FILES), tmp_path / "out", limits())
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "README.md").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "src").stat().st_mode) == 0o700


def test_the_archive_source_serves_an_archive_and_refuses_other_files(tmp_path: Path) -> None:
    archive = zip_of(tmp_path / "a.zip", FILES)
    root = ArchiveSource().materialise(str(archive), limits=limits(), into=tmp_path / "w")
    assert all_files(root) == sorted(FILES)
    notes = tmp_path / "notes.txt"
    notes.write_text("x", encoding="utf-8")
    with pytest.raises(UnsupportedSource):
        ArchiveSource().materialise(str(notes), limits=limits(), into=tmp_path / "w2")
    assert ArchiveSource.owns_root is True


@pytest.mark.parametrize("name", ["bad.zip", "bad.tar.gz"])
def test_a_damaged_archive_is_unsupported_and_leaves_nothing(tmp_path: Path, name: str) -> None:
    bad = tmp_path / name
    bad.write_bytes(b"this is not an archive" * 100)
    with pytest.raises(UnsupportedSource) as raised:
        safe_extract(bad, tmp_path / "out", limits())
    assert not (tmp_path / "out").exists()
    assert name not in str(raised.value)


# --- the hostile corpus --------------------------------------------------------------------------


def rejected_cleanly(tmp_path: Path, archive: Path, expected: type[Exception]) -> Exception:
    guard = tmp_path / "outside"
    guard.mkdir()
    with pytest.raises(expected) as raised:
        safe_extract(archive, tmp_path / "work" / "out", limits())
    assert not (tmp_path / "work" / "out").exists()
    assert list(guard.iterdir()) == []
    assert not (tmp_path / "etc").exists()
    return raised.value


def test_a_path_traversal_entry_is_rejected_in_a_zip(tmp_path: Path) -> None:
    archive = zip_of(tmp_path / "evil.zip", {"ok.txt": "ok", "../../etc/passwd": "root"})
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "traversal"


def test_a_path_traversal_entry_is_rejected_in_a_tar(tmp_path: Path) -> None:
    archive = tar_of(tmp_path / "evil.tar", {"ok.txt": "ok", "../../etc/passwd": "root"})
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "traversal"


def test_an_absolute_entry_is_rejected(tmp_path: Path) -> None:
    archive = tar_of(tmp_path / "evil.tar", {"/tmp/owned": "x"})
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "absolute"


def test_a_symlink_to_etc_is_rejected_in_a_zip(tmp_path: Path) -> None:
    archive = zip_with_symlink(tmp_path / "evil.zip", "link", "/etc")
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "link_escape"


def test_a_symlink_to_etc_is_rejected_in_a_tar(tmp_path: Path) -> None:
    archive = tar_with_members(
        tmp_path / "evil.tar", [member("link", tarfile.SYMTYPE, link="/etc")]
    )
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "link_escape"


def test_a_hard_link_out_of_the_root_is_rejected(tmp_path: Path) -> None:
    archive = tar_with_members(
        tmp_path / "evil.tar", [member("hard", tarfile.LNKTYPE, link="../../etc/passwd")]
    )
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "link_escape"


@pytest.mark.parametrize("kind", [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_a_device_or_fifo_member_is_rejected(tmp_path: Path, kind: bytes) -> None:
    archive = tar_with_members(tmp_path / "evil.tar", [member("dev", kind)])
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "special_member"


def test_a_link_that_stays_inside_the_root_is_skipped_and_never_created(tmp_path: Path) -> None:
    archive = tar_with_members(
        tmp_path / "ok.tar",
        [member("a.txt", size=3), member("alias", tarfile.SYMTYPE, link="a.txt")],
    )
    root = safe_extract(archive, tmp_path / "out", limits())
    assert sorted(p.name for p in root.iterdir()) == ["a.txt"]
    assert not any(p.is_symlink() for p in root.rglob("*"))


def test_a_duplicate_entry_is_rejected(tmp_path: Path) -> None:
    archive = tar_with_members(tmp_path / "dup.tar", [member("a.txt"), member("a.txt")])
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "duplicate"


def test_a_file_where_a_directory_is_needed_is_rejected(tmp_path: Path) -> None:
    archive = tar_with_members(tmp_path / "x.tar", [member("a"), member("a/b.txt")])
    error = rejected_cleanly(tmp_path, archive, UnsafeArchiveEntry)
    assert isinstance(error, UnsafeArchiveEntry) and error.reason == "file_in_path"


# --- limits --------------------------------------------------------------------------------------


def test_a_hundred_thousand_entries_exceed_the_entry_budget(tmp_path: Path) -> None:
    archive = many_entries_tar(tmp_path / "many.tar", 100_000)
    with pytest.raises(LimitExceededError) as raised:
        safe_extract(archive, tmp_path / "out", limits())
    assert raised.value.kind is LimitKind.ARCHIVE_ENTRIES
    assert not (tmp_path / "out").exists()


def test_the_entry_count_is_taken_from_what_is_read(tmp_path: Path) -> None:
    archive = zip_of(tmp_path / "many.zip", {f"f{i}.txt": "x" for i in range(30)})
    with pytest.raises(LimitExceededError) as raised:
        safe_extract(archive, tmp_path / "out", limits(max_files=10))
    assert raised.value.kind is LimitKind.ARCHIVE_ENTRIES


def test_a_file_over_the_per_file_cap_is_refused(tmp_path: Path) -> None:
    archive = tar_of(tmp_path / "big.tar", {"big.txt": "x" * 5000})
    with pytest.raises(LimitExceededError) as raised:
        safe_extract(archive, tmp_path / "out", limits(max_file_size_bytes=1000))
    assert raised.value.kind is LimitKind.FILE_SIZE
    assert not (tmp_path / "out").exists()


def test_a_declared_size_is_not_trusted_when_the_stream_is_longer(tmp_path: Path) -> None:
    class Liar:
        def __init__(self) -> None:
            self._left = 10_000

        def read(self, size: int) -> bytes:
            count = min(size, self._left)
            self._left -= count
            return b"x" * count

    run = archive_module._Run(
        limits=limits(max_file_size_bytes=2000),
        archive_bytes=10**9,
        report=archive_module.ExtractionReport(root=tmp_path),
    )
    with pytest.raises(LimitExceededError) as raised:
        archive_module._write_entry(run, tmp_path, ("a.txt",), 5, Liar())  # type: ignore[arg-type]
    assert raised.value.kind is LimitKind.FILE_SIZE


def test_the_running_total_is_capped(tmp_path: Path) -> None:
    archive = tar_of(tmp_path / "t.tar", {f"f{i}.txt": "x" * 400 for i in range(10)})
    with pytest.raises(LimitExceededError) as raised:
        safe_extract(archive, tmp_path / "out", limits(max_total_bytes=1500))
    assert raised.value.kind is LimitKind.TOTAL_BYTES


def test_a_deep_entry_is_refused(tmp_path: Path) -> None:
    archive = tar_of(tmp_path / "deep.tar", {"a/b/c/d/e.txt": "x"})
    with pytest.raises(LimitExceededError) as raised:
        safe_extract(archive, tmp_path / "out", limits(max_depth=2))
    assert raised.value.kind is LimitKind.DEPTH


def test_a_zip_bomb_is_aborted_by_the_ratio_before_the_total_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bomb = zip_bomb(tmp_path / "bomb.zip", uncompressed=64 * 1024 * 1024)
    seen: list[int] = []
    real = workdir_module.remove_tree

    def measure_then_remove(path: Path) -> None:
        seen.append(tree_size(path))
        real(path)

    monkeypatch.setattr(archive_module, "remove_tree", measure_then_remove)
    budget = 32 * 1024 * 1024
    with pytest.raises(LimitExceededError) as raised:
        safe_extract(
            bomb, tmp_path / "out", limits(max_total_bytes=budget, max_file_size_bytes=budget * 2)
        )
    assert raised.value.kind is LimitKind.ARCHIVE_RATIO
    (written,) = seen
    assert written < budget  # aborted well before the total budget
    assert written <= 100 * bomb.stat().st_size + 2 * CHUNK_BYTES
    assert not (tmp_path / "out").exists()


def test_a_gzip_bomb_is_aborted_by_the_ratio(tmp_path: Path) -> None:
    bomb = tar_gz_bomb(tmp_path / "bomb.tar.gz", uncompressed=64 * 1024 * 1024)
    with pytest.raises(LimitExceededError) as raised:
        safe_extract(bomb, tmp_path / "out", limits(max_file_size_bytes=500_000_000))
    assert raised.value.kind is LimitKind.ARCHIVE_RATIO


def test_the_ratio_is_counted_on_bytes_produced_so_it_trips_mid_entry(tmp_path: Path) -> None:
    run = archive_module._Run(
        limits=limits(max_archive_ratio=10),
        archive_bytes=200_000,
        report=archive_module.ExtractionReport(root=tmp_path),
    )
    run.charge(1_900_000)  # under 10x of the archive
    with pytest.raises(LimitExceededError) as raised:
        run.charge(200_000)  # this chunk crosses it
    assert raised.value.kind is LimitKind.ARCHIVE_RATIO
    assert run.report.bytes_written == 1_900_000  # the crossing chunk was never counted as written


def test_a_small_repetitive_archive_is_below_the_ratio_floor(tmp_path: Path) -> None:
    archive = zip_of(tmp_path / "small.zip", {"zeros.txt": "0" * 500_000})
    root = safe_extract(archive, tmp_path / "out", limits())
    assert (root / "zeros.txt").stat().st_size == 500_000


# --- properties ----------------------------------------------------------------------------------

NAME_ALPHABET = st.sampled_from(
    ["a", "b", ".", "/", "\\", ":", "\x00", " ", "~", "..", "C:", "x/../y"]
)


@settings(max_examples=200, deadline=None)
@given(name=st.lists(NAME_ALPHABET, min_size=0, max_size=8).map("".join))
def test_a_name_that_passes_validation_cannot_leave_the_root(name: str) -> None:
    try:
        parts = entry_parts(name, limits())
    except UnsafeArchiveEntry:
        return
    assert ".." not in parts
    assert all(part and "/" not in part and "\\" not in part for part in parts)
    root = Path("/base/root")
    assert root.joinpath(*parts).is_relative_to(root)


@settings(max_examples=40, deadline=None)
@given(
    names=st.lists(
        st.lists(NAME_ALPHABET, min_size=1, max_size=6).map("".join), min_size=1, max_size=6
    )
)
def test_whatever_the_archive_holds_nothing_is_written_outside_the_root(
    tmp_path_factory: pytest.TempPathFactory, names: list[str]
) -> None:
    base = tmp_path_factory.mktemp("prop")
    guard = base / "guard"
    guard.mkdir()
    (guard / "keep.txt").write_text("keep", encoding="utf-8")
    members = [member(name, size=1) for name in names if "\x00" not in name]
    archive = tar_with_members(base / "a.tar", members)
    try:
        safe_extract(archive, base / "work" / "out", limits())
    except (UnsafeArchiveEntry, LimitExceededError, UnsupportedSource):
        assert not (base / "work" / "out").exists()
    assert all_files(base) == sorted(
        {"a.tar", "guard/keep.txt"}
        | {p.relative_to(base).as_posix() for p in (base / "work").rglob("*") if p.is_file()}
    )
    assert (guard / "keep.txt").read_text(encoding="utf-8") == "keep"
    for path in (base / "work").rglob("*"):
        assert path.resolve().is_relative_to((base / "work" / "out").resolve())
