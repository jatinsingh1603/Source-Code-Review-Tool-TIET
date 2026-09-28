import json
from pathlib import Path

import pytest

from tests.support.cli import run_cli

KAVACHBANK = Path(__file__).resolve().parents[3] / "fixtures" / "kavachbank"
MANIFEST = KAVACHBANK / "manifest.json"


@pytest.mark.skipif(
    not MANIFEST.exists(), reason="Demo 1 path: needs the kavachbank fixture and M1 privacy stages"
)
def test_payloads_contain_no_planted_secret_or_domain_term() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert run_cli(["scan", str(KAVACHBANK), "--profile", "demo"]).exit_code == 0
    result = run_cli(
        ["privacy", "inspect", str(KAVACHBANK), "--limit", "0", "--json", "--include-payload"]
    )
    payloads = " ".join(item["payload_text"] for item in result.json["data"]["payloads"])
    for value in [*manifest.get("secrets", []), *manifest.get("domain_terms", [])]:
        assert str(value) not in payloads
