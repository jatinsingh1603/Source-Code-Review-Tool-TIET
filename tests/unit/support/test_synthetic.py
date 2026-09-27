import zlib
from pathlib import Path

import pytest

from tests.support import synthetic
from tests.support.synthetic import SECRET_SHAPES, build_secret, example_secret

SUPPORT_DIR = Path(synthetic.__file__).parent
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base62(number: int, width: int) -> str:
    digits = ""
    while number:
        number, rest = divmod(number, 62)
        digits = _BASE62[rest] + digits
    return digits.rjust(width, "0")


@pytest.mark.parametrize("kind", sorted(SECRET_SHAPES))
def test_example_is_deterministic_and_matches_pattern(kind: str) -> None:
    first = example_secret(kind)
    assert first == example_secret(kind)
    assert SECRET_SHAPES[kind].pattern.fullmatch(first)


def test_minimum_kinds_present() -> None:
    assert {
        "aws_access_key",
        "github_token",
        "llm_api_key",
        "google_api_key",
        "slack_token",
        "jwt",
        "private_key",
        "bearer",
        "basic_auth_url",
    } <= set(SECRET_SHAPES)


def test_github_example_fails_its_checksum() -> None:
    body = example_secret("github_token")[4:]
    assert body.endswith("000000")
    checksum = _base62(zlib.crc32(body[:30].encode("ascii")), 6)
    assert checksum != body[30:]


def test_build_secret_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="pattern"):
        build_secret("aws_access_key", "ABC")


def test_build_secret_rejects_character_outside_alphabet() -> None:
    with pytest.raises(ValueError, match="alphabet"):
        build_secret("aws_access_key", "abcdefghijklmnop")


def test_build_secret_rejects_unknown_kind() -> None:
    with pytest.raises(KeyError):
        build_secret("no_such_kind", "x")


def _matches(text: str) -> list[tuple[str, int]]:
    return [
        (kind, text.count("\n", 0, match.start()) + 1)
        for kind, shape in SECRET_SHAPES.items()
        for match in shape.pattern.finditer(text)
    ]


def test_strategies_source_has_no_secret_shaped_text() -> None:
    assert _matches((SUPPORT_DIR / "strategies.py").read_text(encoding="utf-8")) == []


def test_synthetic_source_matches_only_at_aws_constants() -> None:
    text = (SUPPORT_DIR / "synthetic.py").read_text(encoding="utf-8")
    lines = text.splitlines()
    for _kind, line_no in _matches(text):
        line = lines[line_no - 1]
        assert line.startswith(
            ("AWS_EXAMPLE_ACCESS_KEY_ID =", "AWS_EXAMPLE_SECRET_ACCESS_KEY =")
        ), line
    assert "AWS_EXAMPLE_ACCESS_KEY_ID" in text
    assert "AWS_EXAMPLE_SECRET_ACCESS_KEY" in text
