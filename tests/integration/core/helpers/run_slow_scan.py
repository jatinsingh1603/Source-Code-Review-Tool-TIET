"""Helper process of ``test_sigint_subprocess``: a fake scan with a slow stage and signal handling.

Run as ``python -m tests.integration.core.helpers.run_slow_scan <repo>`` from the repository
root. ``CK_SLOW_SCAN_MODE`` selects the slow stage: ``cooperative`` (sleeps 30 s and checks for
cancellation), ``stubborn`` (sleeps 30 s without checking) or ``resume`` (no sleep; continues the
latest interrupted scan). The process prints ``STAGE_STARTED`` when the slow stage begins, then
``SCAN <id>`` and ``STATUS <status>`` when ``run_scan`` returns.
"""

import os
import sys
from pathlib import Path

from codekavach.config import load_settings
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from tests.support.pipeline import FakeStage

MODULE = "tests.integration.core.helpers.run_slow_scan"
MODE_VARIABLE = "CK_SLOW_SCAN_MODE"
SALT_HEX = "4b" * 32  # pragma: allowlist secret
SLOW_SECONDS = 30.0


def say(line: str) -> None:
    sys.stdout.write(f"{line}\n")
    sys.stdout.flush()


def mode() -> str:
    return os.environ.get(MODE_VARIABLE, "cooperative")


class AnnouncingStage(FakeStage):
    """Prints ``STAGE_STARTED`` before it starts to sleep."""

    def run(self, ctx: RunContext) -> None:
        say("STAGE_STARTED")
        super().run(ctx)


def ingest() -> FakeStage:
    return FakeStage(
        "ingest",
        requires={"scan.target"},
        provides={"files", "languages"},
        category=StageCategory.INGEST,
        writes={"files": [{"path": "a.py"}], "languages": ["python"]},
    )


def slow() -> FakeStage:
    return AnnouncingStage(
        "analyse-fake",
        requires={"files"},
        provides={"candidates.raw"},
        category=StageCategory.ANALYSE,
        parts={"candidates.raw": []},
        sleep_seconds=0.0 if mode() == "resume" else SLOW_SECONDS,
        cooperative=mode() != "stubborn",
    )


def registry() -> PluginRegistry:
    targets = {"ingest": "ingest", "analyse-fake": "slow"}
    group = "codekavach.stages"
    return PluginRegistry(
        [PluginSpec(group, name, f"{MODULE}:{attr}", "p", "1") for name, attr in targets.items()]
    )


def main(argv: list[str]) -> int:
    repo = Path(argv[1])
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})
    outcome = run_scan(
        loaded,
        str(repo),
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=registry(),
        handle_sigint=True,
        resume="latest" if mode() == "resume" else None,
    )
    say(f"SCAN {outcome.scan.id}")
    say(f"STATUS {outcome.result.status.value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
