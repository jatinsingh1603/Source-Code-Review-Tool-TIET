"""Assert that no listed term occurs in any stored ledger payload (invariant I6, E12-02).

It reuses ``search_payloads`` from the operator-facing ``--check-terms`` command, so the test
checks what an operator would check. It never prints a term: a failure names the number of hits
and the ledger payload hashes.
"""

from collections.abc import Iterable

from codekavach.cli.term_check import Term, search_payloads
from codekavach.privacy.egress.ledger import LedgerReader


def assert_no_terms_in_ledger(
    reader: LedgerReader, terms: Iterable[str], *, min_len: int = 4, ignore_case: bool = True
) -> None:
    """Fail if any term of ``min_len`` or more characters occurs in a payload ``reader`` holds."""
    listed = [
        Term(terms_file="<test>", line=number, text=text)
        for number, text in enumerate(sorted(set(terms)), start=1)
        if len(text) >= min_len
    ]
    stored: list[tuple[str, str]] = []
    for record in reader.records():
        payload = reader.payload_text(record.payload_hash)
        if payload is not None:
            stored.append((record.payload_hash, payload.expose()))
    hits = search_payloads(listed, stored, ignore_case=ignore_case)
    assert not hits, (
        f"{len(hits)} listed term(s) found in ledger payloads "
        f"{sorted({hit.payload_hash[:12] for hit in hits})}"
    )
