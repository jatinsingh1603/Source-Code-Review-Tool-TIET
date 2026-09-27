from pathlib import Path

import pytest

from tests.support.golden import assert_matches_golden


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODEKAVACH_UPDATE_GOLDEN", raising=False)
    monkeypatch.delenv("CI", raising=False)


def test_equal_text_passes(tmp_path: Path) -> None:
    golden = tmp_path / "out.txt"
    golden.write_bytes(b"line one\r\nline two\n")
    assert_matches_golden("line one\r\nline two\n", golden)


def test_different_text_fails_with_unified_diff(tmp_path: Path) -> None:
    golden = tmp_path / "out.txt"
    golden.write_bytes(b"alpha\nbeta\n")
    with pytest.raises(pytest.fail.Exception) as info:
        assert_matches_golden("alpha\ngamma\n", golden)
    message = str(info.value)
    assert "-beta" in message
    assert "+gamma" in message


def test_different_bytes_report_offset(tmp_path: Path) -> None:
    golden = tmp_path / "out.bin"
    golden.write_bytes(b"\x00\x01\x02")
    with pytest.raises(pytest.fail.Exception, match="offset 2"):
        assert_matches_golden(b"\x00\x01\x03", golden)


def test_update_rewrites_locally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    golden = tmp_path / "sub" / "out.txt"
    monkeypatch.setenv("CODEKAVACH_UPDATE_GOLDEN", "1")
    assert_matches_golden("new\n", golden)
    assert golden.read_bytes() == b"new\n"


def test_update_refused_in_ci(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    golden = tmp_path / "out.txt"
    golden.write_bytes(b"old\n")
    monkeypatch.setenv("CODEKAVACH_UPDATE_GOLDEN", "1")
    monkeypatch.setenv("CI", "true")
    with pytest.raises(RuntimeError, match="refused"):
        assert_matches_golden("new\n", golden)
    assert golden.read_bytes() == b"old\n"


def test_missing_golden_fails_without_update(tmp_path: Path) -> None:
    with pytest.raises(pytest.fail.Exception, match="does not exist"):
        assert_matches_golden("x", tmp_path / "missing.txt")
