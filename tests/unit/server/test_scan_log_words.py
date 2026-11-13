"""The scan log words pipeline warning codes for people (no raw machine codes on screen)."""

from typing import Any

from codekavach.core.pipeline.events import WarningRaised
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
