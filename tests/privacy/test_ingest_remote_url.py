"""The git remote URL never reaches an artefact, a record or a log line (E06-02).

The remote names the client, the vendor and often an internal host: adversary A1 of
docs/research/INSIGHTS.md section 4.1 gets re-identification for free from it. The fixture
repository has a remote whose host name is unmistakable; after a scan that ingests it, the whole
state directory (artefacts, manifest, checkpoint, database) and everything logged or printed must
be free of it, and the git metadata reader must not even open ``.git/config``.
"""

import logging
from pathlib import Path

import pytest

from codekavach.config import load_settings
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.ingest.gitmeta import read_git_metadata
from tests.support.ingest import SALT_HEX, ingest_registry

REMOTE_HOST = "git.kavachbank-internal.example.invalid"
COMMIT = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    git_dir = root / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "refs" / "heads" / "main").write_text(COMMIT + "\n", encoding="utf-8")
    (git_dir / "config").write_text(
        f'[remote "origin"]\n\turl = https://{REMOTE_HOST}/payments/core.git\n', encoding="utf-8"
    )
    (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return root


def test_remote_host_is_absent_from_state_logs_and_output(
    repo: Path, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})
    with caplog.at_level(logging.DEBUG):
        outcome = run_scan(
            loaded, str(repo), salt=ScanSalt.from_hex(SALT_HEX), registry=ingest_registry()
        )
        metadata = read_git_metadata(repo)
    assert metadata.commit == COMMIT

    leaked = [
        str(path)
        for path in outcome.state_dir.rglob("*")
        if path.is_file() and REMOTE_HOST.encode() in path.read_bytes()
    ]
    assert leaked == []
    assert REMOTE_HOST not in caplog.text
    captured = capfd.readouterr()
    assert REMOTE_HOST not in captured.out + captured.err
    assert REMOTE_HOST not in outcome.scan.model_dump_json()
    assert REMOTE_HOST not in metadata.model_dump_json()
