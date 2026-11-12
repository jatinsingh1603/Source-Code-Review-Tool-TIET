"""The generated provider reference lists every kind and is current (E22-04)."""

from pathlib import Path

from codekavach.config.models.llm import ProviderKind
from codekavach.llm.providers import docgen

ROOT = Path(__file__).resolve().parents[3]


def test_the_committed_page_is_current() -> None:
    committed = (ROOT / docgen.OUTPUT).read_text(encoding="utf-8")
    assert committed == docgen.render(), (
        "docs/reference/providers.md is stale; run: "
        "uv run python -m codekavach.llm.providers.docgen"
    )


def test_every_kind_is_listed() -> None:
    page = docgen.render()
    for kind in ProviderKind:
        assert f"| `{kind.value}` |" in page
