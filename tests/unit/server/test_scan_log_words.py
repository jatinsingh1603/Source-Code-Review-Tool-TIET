"""The scan log words pipeline warning codes for people (no raw machine codes on screen)."""

from typing import Any

from codekavach.core.pipeline.events import ItemReviewed, WarningRaised
from codekavach.server.jobs.scan import _Progress


class _Log:
    def __init__(self) -> None:
        self.lines: list[tuple[str, dict[str, Any]]] = []

    def append(self, kind: str, data: dict[str, Any]) -> None:
        self.lines.append((kind, data))


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
