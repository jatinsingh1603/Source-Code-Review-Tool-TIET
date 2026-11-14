"""The scan log words pipeline warning codes for people (no raw machine codes on screen)."""

from importlib.metadata import entry_points
from typing import Any

from codekavach.core.pipeline.events import ItemReviewed, WarningRaised
from codekavach.server.jobs.scan import STAGE_LABELS, _opening_words, _Progress


class _Log:
    def __init__(self) -> None:
        self.lines: list[tuple[str, dict[str, Any]]] = []

    def append(self, kind: str, data: dict[str, Any]) -> None:
        self.lines.append((kind, data))


def _engines_ended(total: int | None) -> list[str]:
    log = _Log()
    progress = _Progress.__new__(_Progress)
    progress.log = log  # type: ignore[assignment]
    progress.done, progress.total, progress.limited, progress.failed = 0, 10, {}, {}
    progress.counts = {} if total is None else {"analyse-engines": (total, total)}
    progress._update = lambda **_: None  # type: ignore[method-assign]
    progress._stage_ended("stage.finished", "analyse-engines", "Running external engines", {})
    return [str(data["message"]) for kind, data in log.lines if kind == "log"]


def test_the_log_says_when_no_external_engine_ran() -> None:
    assert any(line.startswith("No external engine") for line in _engines_ended(None))
    assert not any(line.startswith("No external engine") for line in _engines_ended(2))


def _logged(code: str) -> str:
    log = _Log()
    progress = _Progress.__new__(_Progress)
    progress.log = log  # type: ignore[assignment]
    progress.handle(WarningRaised(scan_id="scn_1", stage="analyse-engines", code=code))
    ((kind, data),) = log.lines
    assert (kind, data["level"]) == ("log", "warning")
    return str(data["message"])


def test_a_known_warning_code_is_worded() -> None:
    message = _logged("engine_network_not_isolated")
    assert "engine_network_not_isolated" not in message
    assert message.startswith("External engines ran without network isolation")


def test_an_unknown_warning_code_is_shown_as_it_is() -> None:
    assert _logged("something_new") == "something_new"


def _verdict_line(verdict: str, confidence: str) -> str:
    log = _Log()
    progress = _Progress.__new__(_Progress)
    progress.log = log  # type: ignore[assignment]
    progress.queued = {"cand_1": ("critical", [89])}
    progress.handle(
        ItemReviewed(
            scan_id="scn_1", stage="llm-review", item_id="cand_1", verdict=verdict,
            confidence=confidence, current=1, total=3,
        )
    )  # fmt: skip
    ((kind, data),) = log.lines
    assert kind == "finding"
    return str(data["title"])


def test_a_confident_verdict_reads_confirmed() -> None:
    line = _verdict_line("vulnerable", "high")
    assert line == "1 of 3 · CWE-89 (critical): confirmed by the model"


def test_a_low_confidence_verdict_reads_needs_review_like_the_findings_table() -> None:
    for confidence in ("low", "medium"):
        line = _verdict_line("vulnerable", confidence)
        assert "confirmed" not in line
        assert line.endswith("low confidence: needs review")
    assert _verdict_line("not_vulnerable", "low").endswith("judged not exploitable by the model")


def test_every_built_in_stage_has_a_label_for_the_log() -> None:
    """The live log says "Scanning for secrets done in 431 ms", never "analyse-secrets done"."""
    names = {entry.name for entry in entry_points(group="codekavach.stages")}
    assert names
    assert names - set(STAGE_LABELS) == set()


def test_an_l0_scan_does_not_say_payloads_are_sent() -> None:
    l0 = _opening_words({"level": "L0", "provider": "mock", "send": True}, remote=False)
    assert "payloads sent" not in l0
    assert "nothing is sent to a model" in l0
    l3 = _opening_words({"level": "L3", "provider": "mock", "send": True}, remote=False)
    assert l3 == "Privacy level L3; provider mock (local); payloads sent"
