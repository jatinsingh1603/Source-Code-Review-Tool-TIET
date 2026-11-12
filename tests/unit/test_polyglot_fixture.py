"""The polyglot fixture: every planted line is where the ground truth says, in every language."""

from pathlib import Path

import pytest
import yaml
from tree_sitter_language_pack import get_parser

ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "polyglot"
MANIFEST = yaml.safe_load((ROOT / "ground-truth" / "manifest.yaml").read_text(encoding="utf-8"))
GRAMMAR = {
    ".py": "python",
    ".js": "javascript",
    ".kt": "kotlin",
    ".php": "php",
    ".cs": "csharp",
    ".rb": "ruby",
    ".c": "c",
    ".cpp": "cpp",
}


def test_the_manifest_covers_every_new_language() -> None:
    assert {Path(item["file"]).suffix for item in MANIFEST["planted_vulnerabilities"]} == set(
        GRAMMAR
    )


@pytest.mark.parametrize("item", MANIFEST["planted_vulnerabilities"], ids=lambda i: i["id"])
def test_a_planted_line_names_its_id(item: dict[str, object]) -> None:
    lines = (ROOT / str(item["file"])).read_text(encoding="utf-8").splitlines()
    assert str(item["id"]) in lines[int(str(item["line"])) - 1]


@pytest.mark.parametrize("path", sorted((ROOT / "src").iterdir()), ids=lambda p: p.name)
def test_every_file_parses_without_a_syntax_error(path: Path) -> None:
    tree = get_parser(GRAMMAR[path.suffix]).parse(path.read_bytes())  # type: ignore[arg-type]
    assert not tree.root_node.has_error
