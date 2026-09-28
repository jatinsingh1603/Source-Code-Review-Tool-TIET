"""Stage factories used as entry-point targets by fake distributions in integration tests.

``FAIL_ANALYSIS`` makes ``analyse-fake`` raise; ``CALLS`` records which egress stages ran.
"""

from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory
from tests.support.pipeline import FakeStage

FAIL_ANALYSIS: list[bool] = [False]
CALLS: list[str] = []


class TrackedStage(FakeStage):
    """A fake stage that records every call in ``CALLS``."""

    def run(self, ctx: RunContext) -> None:
        CALLS.append(self.name)
        super().run(ctx)


def ingest() -> FakeStage:
    return FakeStage(
        "ingest",
        requires={"scan.target"},
        provides={"files", "languages"},
        category=StageCategory.INGEST,
        writes={"files": [{"path": "a.py"}], "languages": ["python"]},
    )


def analyse_fake() -> FakeStage:
    return FakeStage(
        "analyse-fake",
        requires={"files"},
        provides={"candidates.raw"},
        category=StageCategory.ANALYSE,
        parts={"candidates.raw": []},
        raises=RuntimeError("boom") if FAIL_ANALYSIS[0] else None,
    )


def aggregate() -> FakeStage:
    return FakeStage(
        "aggregate",
        requires={"candidates.raw"},
        provides={"candidates"},
        category=StageCategory.AGGREGATE,
        writes={"candidates": []},
    )


def rate() -> FakeStage:
    return FakeStage(
        "rate",
        requires={"candidates"},
        provides={"findings"},
        category=StageCategory.RATE,
        writes={"findings": []},
    )


def privacy() -> FakeStage:
    return TrackedStage(
        "privacy-prepare",
        requires={"candidates"},
        provides={"payloads.sanitised"},
        category=StageCategory.PRIVACY,
    )


def llm() -> FakeStage:
    return TrackedStage(
        "llm-review",
        requires={"payloads.sanitised"},
        provides={"verdicts.raw"},
        category=StageCategory.LLM,
    )


PARTIAL_MANIFESTS: list[object] = []


class ManifestReadingStage(FakeStage):
    """A REPORT stage that records the partial manifest of the run so far (E04-24)."""

    def run(self, ctx: RunContext) -> None:
        PARTIAL_MANIFESTS.append(ctx.partial_manifest())
        super().run(ctx)


def report() -> FakeStage:
    return ManifestReadingStage(
        "report",
        requires={"findings"},
        provides={"report.outputs"},
        category=StageCategory.REPORT,
    )
