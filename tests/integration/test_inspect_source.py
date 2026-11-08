"""``privacy inspect`` over a real scan: the payload source and the two-column page (E13-03)."""

import re
from pathlib import Path

import pytest

from codekavach.cli.inspect_page import render_page, write_page
from codekavach.cli.privacy import collect
from codekavach.config import load_settings
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.inspect_source import open_payload_source
from tests.integration.test_privacy_pipeline import (  # noqa: F401 - the autouse passphrase
    ENV,
    Run,
    copy_fixture,
    run_and_capture,
    vault_passphrase,
)

EXTERNAL = re.compile(r"(?:src|href)\s*=\s*[\"']?\s*(?:https?:|//)|url\(|@import|<script\b|<img\b")


@pytest.fixture(scope="module")
def root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return copy_fixture(tmp_path_factory.mktemp("inspect"))


def source_of(root: Path, run: Run, home: str) -> object:
    loaded = load_settings(
        target=root, env={"CODEKAVACH_HOME": str(root.parent / home), **ENV}, cli_overrides=None
    )
    return open_payload_source(
        StateLayout(run.outcome.state_dir), str(run.outcome.scan.id), settings=loaded.settings
    )


def test_every_sent_payload_is_rebuilt_from_the_index_and_the_ledger(root: Path) -> None:
    run = run_and_capture(root, home="home-inspect")
    source = source_of(root, run, "home-inspect")
    scan_id = str(run.outcome.scan.id)
    rebuilt = list(source.payloads(scan_id))  # type: ignore[attr-defined]
    assert {p.payload_hash for p in rebuilt} == {p.payload_hash for p in run.payloads}
    assert {p.text.expose() for p in rebuilt} == {p.text.expose() for p in run.payloads}
    for payload in rebuilt:
        candidate_id = str(payload.candidate_id)
        assert source.candidate(candidate_id) is not None  # type: ignore[attr-defined]
        assert source.slice_for(candidate_id) is not None  # type: ignore[attr-defined]
        assert source.ledger_outcome(payload.payload_hash) == "sent"  # type: ignore[attr-defined]


def test_the_page_pairs_original_and_payload_and_is_self_contained(
    root: Path, tmp_path: Path
) -> None:
    run = run_and_capture(root, home="home-inspect-page")
    source = source_of(root, run, "home-inspect-page")
    scan_id = str(run.outcome.scan.id)
    entries = [e for e in collect(source, scan_id, [], None) if e.hash_ok]  # type: ignore[arg-type]
    assert len(entries) == len(run.payloads) > 0
    page = render_page(entries, scan_id=scan_id, provider_kind="mock")
    assert not EXTERNAL.search(page) and "Content-Security-Policy" in page
    for entry in entries:
        assert entry.payload.payload_hash in page
    assert 'class="redacted"' in page or 'class="renamed"' in page
    assert "answers locally" in page  # the mock provider is named for what it is
    out = write_page(tmp_path / "demo" / "inspect.html", page)
    assert out.read_text(encoding="utf-8") == page


def test_a_no_send_scan_is_inspectable_and_its_outcome_is_recorded(root: Path) -> None:
    run = run_and_capture(root, no_send=True, home="home-inspect-dry")
    source = source_of(root, run, "home-inspect-dry")
    payloads = list(source.payloads(str(run.outcome.scan.id)))  # type: ignore[attr-defined]
    assert payloads
    assert {source.ledger_outcome(p.payload_hash) for p in payloads} == {"recorded"}  # type: ignore[attr-defined]
