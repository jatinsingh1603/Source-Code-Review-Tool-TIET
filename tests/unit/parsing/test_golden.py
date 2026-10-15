"""Golden node-type sequence of a fixed sample file (E07-01).

Pins the tree-sitter Python grammar's exact node-type sequence for one fixed file, so that
bumping tree-sitter-language-pack (``PINNED_PACK_VERSION``) shows up as a diff against this file
instead of a silent change in what ``parse`` extracts.
"""

from pathlib import Path

import tree_sitter as ts

from codekavach.core.models import Language
from codekavach.parsing.loader import load_language
from tests.support.golden import assert_matches_golden

SAMPLE = Path(__file__).resolve().parents[2] / "fixtures" / "parsing" / "sample_python.txt"
GOLDEN = Path(__file__).parent / "golden" / "sample_python_node_types.txt"


def _node_type_sequence(source: bytes) -> str:
    tree = ts.Parser(load_language(Language.PYTHON)).parse(source)
    types: list[str] = []

    def walk(node: ts.Node) -> None:
        types.append(node.type)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return "\n".join(types) + "\n"


def test_sample_file_node_type_sequence_matches_golden() -> None:
    source = SAMPLE.read_bytes()
    assert_matches_golden(_node_type_sequence(source), GOLDEN)
