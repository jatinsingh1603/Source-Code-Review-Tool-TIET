"""The scan manifest records the memo statistics of a real ``run_scan`` (E04-22, E04-24)."""

import json
from pathlib import Path

from codekavach.config import load_settings
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.registry import PluginRegistry
from tests.support.pipeline import write_fake_distribution

STAGE_SOURCE = """
from pydantic import BaseModel

from codekavach.core.pipeline.memo import memo_key
from codekavach.core.pipeline.stage import StageCategory


class Row(BaseModel):
    name: str


class Parse:
    name = "parse"
    requires = frozenset({"scan.target"})
    provides = frozenset({"parsed"})
    category = StageCategory.PARSE
    version = "1"

    def run(self, ctx):
        for index in range(3):
            ctx.memo.get_or_compute(
                "manifest.rows.v1",
                memo_key(str(index)),
                lambda index=index: Row(name=str(index)),
                Row,
            )
        ctx.artefacts.put("parsed", {"ok": True})
"""


def test_the_manifest_counts_memo_hits_and_misses(fake_site: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    write_fake_distribution(
        fake_site,
        "ck-memo-stage",
        "1.0",
        entry_points={"codekavach.stages": {"parse": "ck_memo_stage:Parse"}},
        modules={"ck_memo_stage.py": STAGE_SOURCE},
    )
    config = load_settings(target=repo, env={"CODEKAVACH_HOME": str(tmp_path / "home")})

    def scan() -> tuple[int, int]:
        registry = PluginRegistry([s for s in discover() if s.dist_name == "ck-memo-stage"])
        outcome = run_scan(
            config,
            str(repo),
            salt=ScanSalt.from_hex("7a" * 32),
            registry=registry,
            refresh=["parse"],  # bypass the stage cache so that the memo decides
        )
        assert outcome.manifest_path is not None
        counters = json.loads(outcome.manifest_path.read_text(encoding="utf-8"))["counters"]
        assert (outcome.result.memo_hits, outcome.result.memo_misses) == (
            counters["memo_hits"],
            counters["memo_misses"],
        )
        return counters["memo_hits"], counters["memo_misses"]

    assert scan() == (0, 3)
    assert scan() == (3, 0)
