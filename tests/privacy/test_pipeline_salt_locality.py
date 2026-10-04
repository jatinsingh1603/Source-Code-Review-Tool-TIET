"""Regression guard for I3: the scan salt never reaches the state directory."""

from pathlib import Path

from codekavach.config import load_settings
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry

SALT_HEX = "c3" * 32  # pragma: allowlist secret
TARGETS = {
    "ingest": "ingest",
    "analyse-fake": "analyse_fake",
    "aggregate": "aggregate",
    "rate": "rate",
}


def test_salt_is_not_written_below_the_state_directory(tmp_path: Path) -> None:
    registry = PluginRegistry(
        [
            PluginSpec(
                "codekavach.stages", name, f"tests.support.fake_stages_module:{attr}", "p", "1"
            )
            for name, attr in TARGETS.items()
        ]
    )
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(tmp_path / "home")})
    outcome = run_scan(loaded, str(repo), salt=ScanSalt.from_hex(SALT_HEX), registry=registry)
    files = [path for path in outcome.state_dir.rglob("*") if path.is_file()]
    assert files
    assert outcome.state_dir / "codekavach.db" in files  # the local database is checked too
    for path in files:
        data = path.read_bytes()
        assert SALT_HEX.encode() not in data
        assert bytes.fromhex(SALT_HEX) not in data
