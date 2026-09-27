import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load() -> ModuleType:
    path = REPO_ROOT / "tools/dev/forbid_runtime_artefacts.py"
    spec = importlib.util.spec_from_file_location("forbid_runtime_artefacts", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["forbid_runtime_artefacts"] = module
    spec.loader.exec_module(module)
    return module


guard = _load()

REJECTED = [
    "a.vault",
    "dir/b.VAULT",
    "x.ledger.jsonl",
    ".codekavach/db.sqlite",
    "sub/.codekavach/x",
    ".env",
    ".env.local",
    "config/codekavach.local.toml",
    "server.pem",
    "scan-output/r.json",
    "reports-out/a.pdf",
    "certs/client.p12",
    "src\\app\\.env",
]
ACCEPTED = [
    ".env.example",
    "docs/vault.md",
    "src/codekavach/privacy/vault/__init__.py",
    "tests/fixtures/keys/fake.pem",
    "fixtures/kavachbank/certs/fake.key",
    "ledger.py",
    "config/.environment.md",
]


@pytest.mark.parametrize("path", REJECTED)
def test_rejected(path: str) -> None:
    assert guard.offending([path]) == [path]


@pytest.mark.parametrize("path", ACCEPTED)
def test_accepted(path: str) -> None:
    assert guard.offending([path]) == []


def test_command_line(capsys: pytest.CaptureFixture[str]) -> None:
    assert guard.main([]) == 0
    assert guard.main(["README.md", "a.vault", ".env"]) == 1
    err = capsys.readouterr().err
    assert "a.vault" in err
    assert ".env" in err
    assert "README.md" not in err
