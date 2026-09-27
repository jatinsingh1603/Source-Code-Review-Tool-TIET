import re

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from codekavach.core.models import FingerprintInputError
from codekavach.core.models.fingerprint import (
    FINGERPRINT_PATTERN,
    SARIF_PARTIAL_FINGERPRINT_KEY,
    FingerprintParts,
    compute_correlation_key,
    compute_fingerprint,
    fingerprint_batch,
    normalise_snippet,
    snippet_hash,
)
from tests.support.synthetic import AWS_EXAMPLE_ACCESS_KEY_ID

LINE_A = '        cur.execute("SELECT * FROM accounts WHERE owner = \'" + owner + "\'")'
# pragma: allowlist nextline secret
HASH_A = "9867178e39754d0a9269ea7d0e3c00b5e209e8d51eb77e229cc33b4aa04bb6dc"
# pragma: allowlist nextline secret
EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def parts(**overrides: object) -> FingerprintParts:
    fields: dict[str, object] = {
        "engine": "codekavach-rules",
        "rule_id": "python.sqli.string-concat",
        "path": "src/bank/accounts.py",
        "symbol": "AccountRepo.find_by_owner",
        "snippet_hash": HASH_A,
    }
    fields.update(overrides)
    return FingerprintParts.model_validate(fields)


def test_vector_a() -> None:
    assert snippet_hash([LINE_A]) == HASH_A
    assert compute_fingerprint(parts()) == "ckfp1:58d192700c1c56f2f97f4e2ae1ec20ee"
    assert compute_fingerprint(parts(), 1) == "ckfp1:c6231668280832ecd7b3107fbc0825c4"
    assert (
        compute_correlation_key(89, "src/bank/accounts.py", "AccountRepo.find_by_owner", HASH_A)
        == "ckck1:53fd354cc11c0db1b4ba659bb73d4189"
    )


def test_vector_b_equals_a() -> None:
    line = '\tcur.execute("SELECT * FROM accounts   WHERE owner = \'" + owner + "\'")   \r'
    fingerprint = compute_fingerprint(
        parts(
            engine="CodeKavach-Rules ",
            path=r".\src\bank\accounts.py",
            snippet_hash=snippet_hash([line]),
        )
    )
    assert fingerprint == "ckfp1:58d192700c1c56f2f97f4e2ae1ec20ee"


def test_vector_e() -> None:
    lines = [f'API_KEY = "{AWS_EXAMPLE_ACCESS_KEY_ID}"', "", "   DEBUG = True  "]
    assert normalise_snippet(lines) == f'API_KEY = "{AWS_EXAMPLE_ACCESS_KEY_ID}"\nDEBUG = True'
    digest = snippet_hash(lines)
    # pragma: allowlist nextline secret
    assert digest == "222d88a0743ae3767b7e54f3c00199210371e49d751f475519cb02187aaa4210"
    fingerprint = compute_fingerprint(
        parts(
            engine="codekavach-secrets",
            rule_id="aws-access-key",
            path="config/settings.py",
            symbol=None,
            snippet_hash=digest,
        )
    )
    assert fingerprint == "ckfp1:136c879a69c862ce44b11e5938444d56"


def test_vector_f() -> None:
    fingerprint = compute_fingerprint(
        parts(
            engine="codekavach-sca",
            rule_id="GHSA-xxxx",
            path="requirements.txt",
            symbol=None,
            snippet_hash=snippet_hash(["pkg:pypi/django"]),
        )
    )
    assert fingerprint == "ckfp1:22930ffc5f18d997b6d2613e7dadad6c"


def test_empty_snippet_and_constants() -> None:
    assert snippet_hash([]) == EMPTY_HASH
    assert re.match(FINGERPRINT_PATTERN, compute_fingerprint(parts()))
    assert SARIF_PARTIAL_FINGERPRINT_KEY == "codekavachFingerprint/v1"


def test_fifty_line_cap() -> None:
    lines = [f"x = {i}" for i in range(50)]
    assert snippet_hash([*lines, "line 51"]) == snippet_hash([*lines, "something else"])
    assert snippet_hash([*lines[:49], "changed"]) != snippet_hash(lines)


def test_batch_numbers_occurrences_by_line() -> None:
    items = [parts(start_line=30), parts(start_line=10), parts(start_line=20)]
    expected = [compute_fingerprint(parts(), n) for n in (2, 0, 1)]
    assert fingerprint_batch(items) == expected


def test_batch_ties_use_input_order() -> None:
    items = [parts(start_line=5), parts(start_line=5)]
    assert fingerprint_batch(items) == [
        compute_fingerprint(parts(), 0),
        compute_fingerprint(parts(), 1),
    ]


@pytest.mark.parametrize(
    ("overrides", "occurrence"),
    [
        ({"engine": "a\x1fb"}, 0),
        ({"rule_id": "r\x1f"}, 0),
        ({"symbol": "s\x1f"}, 0),
        ({"engine": "   "}, 0),
        ({"rule_id": ""}, 0),
        ({}, -1),
        ({"snippet_hash": "ABC"}, 0),
        ({"snippet_hash": HASH_A.upper()}, 0),
    ],
)
def test_input_errors(overrides: dict[str, object], occurrence: int) -> None:
    with pytest.raises(FingerprintInputError):
        compute_fingerprint(parts(**overrides), occurrence)


def test_path_with_separator_rejected() -> None:
    bad = parts().model_copy(update={"path": "src/a\x1fb.py"})
    with pytest.raises(FingerprintInputError):
        compute_fingerprint(bad)


def test_correlation_key_errors() -> None:
    with pytest.raises(FingerprintInputError):
        compute_correlation_key(89, "a.py", "s\x1f", HASH_A)
    with pytest.raises(FingerprintInputError):
        compute_correlation_key(89, "a.py", None, "nothex")
    with pytest.raises(FingerprintInputError):
        compute_correlation_key(89, "../a.py", None, HASH_A)


def test_correlation_key_ignores_engine_and_rule() -> None:
    key = compute_correlation_key(89, "src/bank/accounts.py", "AccountRepo.find_by_owner", HASH_A)
    assert key == compute_correlation_key(
        89, r"src\bank\accounts.py", "AccountRepo.find_by_owner", HASH_A
    )
    assert key != compute_correlation_key(
        564, "src/bank/accounts.py", "AccountRepo.find_by_owner", HASH_A
    )


# properties

_code_line = st.text(
    alphabet=st.characters(codec="utf-8", blacklist_characters="\r\n"), max_size=30
)
_whitespace = st.text(alphabet=" \t\x0b\x0c", max_size=4)


def _fp(lines: list[str], **overrides: object) -> str:
    return compute_fingerprint(parts(snippet_hash=snippet_hash(lines), **overrides))


@given(st.lists(_code_line, min_size=1, max_size=8), st.data())
def test_invariant_under_whitespace_blank_lines_crlf_and_line_number(
    lines: list[str], data: st.DataObject
) -> None:
    base = _fp(lines)
    padded = [data.draw(_whitespace) + line + data.draw(_whitespace) for line in lines]
    assert _fp(padded) == base
    with_blanks = [item for line in lines for item in (line, data.draw(_whitespace))]
    assert _fp(with_blanks) == base
    assert _fp([line + "\r" for line in lines]) == base
    assert _fp(lines, start_line=data.draw(st.integers(1, 10_000))) == base


_word = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=10)


@given(
    st.sampled_from(["engine", "rule_id", "path", "symbol", "snippet"]),
    _word,
)
def test_any_identity_change_changes_fingerprint(field: str, suffix: str) -> None:
    base = compute_fingerprint(parts())
    if field == "snippet":
        changed = compute_fingerprint(parts(snippet_hash=snippet_hash([LINE_A + suffix])))
    elif field == "path":
        changed = compute_fingerprint(parts(path=f"src/bank/{suffix}.py"))
        assume(suffix != "accounts")
    else:
        original = str(getattr(parts(), field))
        changed = compute_fingerprint(parts(**{field: original + suffix}))
    assert changed != base


@given(st.lists(st.tuples(st.integers(0, 3), st.integers(1, 50)), max_size=30, unique=True))
def test_batch_results_distinct(pairs: list[tuple[int, int]]) -> None:
    items = [parts(rule_id=f"rule-{group}", start_line=line) for group, line in pairs]
    results = fingerprint_batch(items)
    assert len(set(results)) == len(results)
