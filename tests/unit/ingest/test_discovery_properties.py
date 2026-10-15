"""Property tests for discovery (E06-01): line counting and permutation invariance."""

from hypothesis import given
from hypothesis import strategies as st

from codekavach.config.models.ingest import IngestSettings
from codekavach.config.models.root import Settings
from codekavach.core.models import split_lines
from codekavach.ingest.discovery import discover
from tests.support.synthetic import make_tree

_LINE_ALPHABET = st.text(alphabet="ab\r\n", min_size=0, max_size=200)


@given(text=_LINE_ALPHABET)
def test_line_count_always_equals_split_lines(text: str) -> None:
    root = make_tree({"a.txt": text})
    files = discover(root, Settings(ingest=IngestSettings()))
    assert files[0].line_count == len(split_lines(text))


@given(order=st.permutations(range(10)))
def test_discover_output_is_invariant_under_creation_order(order: tuple[int, ...]) -> None:
    root = make_tree({})
    for index in order:
        (root / f"f{index}.py").write_text(f"x = {index}\n", encoding="utf-8")
    files = discover(root, Settings(ingest=IngestSettings()))
    assert [f.path for f in files] == sorted(f"f{i}.py" for i in range(10))
