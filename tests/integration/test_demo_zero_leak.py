"""The Demo 1 run end to end: zero leakage, offline, and a refusal of a remote provider (E13-03)."""

import socket
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from codekavach.cli import demo_runner
from codekavach.cli.demo_runner import DemoReport, run_demo
from codekavach.cli.errors import PrivacyBlockError, UsageError
from codekavach.cli.term_check import load_terms
from codekavach.config import load_settings
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.egress.ledger import open_reader
from tests.support.kavachbank import FIXTURE_ROOT, TERMS_PATH, load_manifest, resolve_value_ref
from tests.support.ledger_terms import assert_no_terms_in_ledger


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The demo is offline: any attempt to open a connection fails the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    yield


PASSPHRASE = "synthetic passphrase for tests only"


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[DemoReport, Path]]:
    """One real demo run, with a known passphrase so the test can reopen its ledger."""
    out = tmp_path_factory.mktemp("demo") / "out"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(demo_runner, "secrets", SimpleNamespace(token_hex=lambda size: PASSPHRASE))
        report = run_demo(str(FIXTURE_ROOT), out, keep_state=True)
    yield report, out


def test_the_demo_passes_every_check_and_names_the_provider(
    demo: tuple[DemoReport, Path],
) -> None:
    report, _ = demo
    assert report.provider == "mock"
    assert report.chain_ok and report.payloads_ok
    assert report.zero_leak_passed and report.zero_leak_occurrences == 0
    assert report.zero_leak_checked > 0
    assert report.findings > 0 and report.payloads > 0
    assert "would have been sent" in report.note and "opens no connection" in report.note


def test_no_listed_term_occurs_in_any_ledger_payload(
    demo: tuple[DemoReport, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    report, out = demo
    assert report.state_dir is not None
    monkeypatch.setenv(demo_runner.PASSPHRASE_VARIABLE, PASSPHRASE)
    loaded = load_settings(
        target=out / ".work" / "kavachbank",
        env={
            "CODEKAVACH_HOME": str(out / ".work" / "home"),
            "CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE": "passphrase",
            "CODEKAVACH_PRIVACY__VAULT__PASSPHRASE": f"env:{demo_runner.PASSPHRASE_VARIABLE}",
        },
        cli_overrides=None,
    )
    reader = open_reader(StateLayout(report.state_dir), settings=loaded.settings)
    terms = [term.text for term in load_terms(TERMS_PATH).terms]
    assert len(terms) == report.zero_leak_checked
    assert any(reader.payload_text(record.payload_hash) for record in reader.records())
    assert_no_terms_in_ledger(reader, terms)


def test_the_demo_writes_the_inspection_page_the_report_and_the_verification(
    demo: tuple[DemoReport, Path],
) -> None:
    report, out = demo
    assert (out / "inspect.html").is_file() and (out / "report.html").is_file()
    verification = (out / "verification.txt").read_text(encoding="utf-8")
    assert "[ok] chain" in verification and "[ok] terms" in verification
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "listed terms searched in every ledger payload: no occurrence" in page
    assert any(item.startswith("html report") for item in report.files)
    # The report is the client's own document and quotes its code: IaC and dependency findings
    # cite configuration files that name the organisation. What must never be printed anywhere is
    # a planted secret or personal data, or a domain term other than the organisation's name. The
    # zero-leak claim itself is about the ledger payloads, checked above.
    manifest = load_manifest()
    secret_lines = {
        line
        for secret in manifest.planted_secrets
        for line in resolve_value_ref(secret.value_ref).split("\n")
    }
    for line in secret_lines:
        assert line not in page
    for pii in manifest.planted_pii:
        assert resolve_value_ref(pii.value_ref) not in page, pii.id
    organisation = manifest.application.name.lower()
    for term in load_terms(TERMS_PATH).terms:
        if term.text.lower() != organisation:
            assert term.text not in page
    assert "inspect.html" not in page and "Original code" not in page  # client code stays out


def test_the_fixture_is_left_untouched(demo: tuple[DemoReport, Path]) -> None:
    assert not (FIXTURE_ROOT / ".codekavach").exists()
    assert not (FIXTURE_ROOT / ".git").exists()


def test_a_remote_provider_is_refused_before_anything_is_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("the scan must not start")

    monkeypatch.setattr(demo_runner, "_provider_kind", lambda loaded: "openai")
    monkeypatch.setattr(demo_runner, "run_scan", fail)
    with pytest.raises(UsageError) as raised:
        run_demo(str(FIXTURE_ROOT), tmp_path / "out")
    assert raised.value.code == "demo_remote_provider"
    assert not (tmp_path / "out" / ".work").exists()  # the working copy is removed


def test_a_term_in_the_ledger_fails_the_demo_and_keeps_the_evidence(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    for path in FIXTURE_ROOT.rglob("*"):
        relative = path.relative_to(FIXTURE_ROOT)
        if path.is_file() and relative.parts[0] != "ground-truth":
            (fixture / relative).parent.mkdir(parents=True, exist_ok=True)
            (fixture / relative).write_bytes(path.read_bytes())
    # Source code keeps its keywords in a payload. Listing one as a term must trip the check,
    # which shows the demo fails closed instead of reporting a pass it did not earn.
    (fixture / "ground-truth").mkdir()
    (fixture / "ground-truth" / "terms.txt").write_text("return" + chr(10), encoding="utf-8")
    with pytest.raises(PrivacyBlockError) as raised:
        run_demo(str(fixture), tmp_path / "out")
    assert raised.value.code == "demo_verification_failed"
    assert "[FAILED] terms" in (tmp_path / "out" / "verification.txt").read_text(encoding="utf-8")
