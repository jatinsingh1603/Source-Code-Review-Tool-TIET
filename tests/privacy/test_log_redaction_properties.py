"""Property tests of the log redaction processor (I3, R1): no secret survives into a log line."""

import json
import re
import uuid
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.log.redaction import RedactionProcessor, scrub_text
from tests.support.strategies import fake_secrets, nested_json

PROCESSOR = RedactionProcessor()
keys = st.text("abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=12)
leaves = st.integers() | st.text(max_size=8) | st.none()


def place(tree: Any, secret: str, path: list[int]) -> Any:
    """Put ``secret`` somewhere inside ``tree`` (following ``path`` choices)."""
    if isinstance(tree, dict) and tree and path:
        key = sorted(tree)[path[0] % len(tree)]
        return {**tree, key: place(tree[key], secret, path[1:])}
    if isinstance(tree, (list, tuple)) and tree and path:
        items = list(tree)
        index = path[0] % len(items)
        items[index] = place(items[index], secret, path[1:])
        return items
    return f"prefix {secret} suffix"


@given(
    fake_secrets(),
    nested_json(leaves),
    st.lists(st.integers(0, 10), max_size=6),
    keys,
)
def test_secret_never_rendered(
    secret: tuple[str, str], tree: Any, path: list[int], key: str
) -> None:
    _, value = secret
    event = {"event": "probe", key: place(tree, value, path)}
    rendered = json.dumps(PROCESSOR(None, "info", event), default=repr)
    for piece in re.split(r"\s+", value):
        if len(piece) >= 12:
            assert piece not in rendered


@given(st.text())
def test_scrub_is_idempotent(text: str) -> None:
    once = scrub_text(text)
    assert scrub_text(once) == once


@given(st.dictionaries(keys | st.integers(), nested_json(leaves) | leaves, max_size=6))
def test_processor_never_raises(event: dict[Any, Any]) -> None:
    result = PROCESSOR(None, "info", event)
    assert isinstance(result, dict)
    assert "event" in result or "event" not in event


@given(
    st.binary(min_size=20, max_size=20).map(bytes.hex)
    | st.binary(min_size=32, max_size=32).map(bytes.hex)
    | st.builds(lambda: str(uuid.uuid4()))
    | st.integers().map(str)
)
def test_digests_uuids_and_integers_pass(value: str) -> None:
    assert scrub_text(value) == value
    assert PROCESSOR(None, "info", {"event": "e", "digest": value})["digest"] == value
