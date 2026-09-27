import asyncio
import io
import json
import logging
import os
import re
import threading
from collections.abc import Iterator
from typing import Any

import pytest
import structlog
from structlog.typing import EventDict, WrappedLogger

import codekavach.cli.app
from codekavach.core.log import (
    bind_scan_context,
    clear_scan_context,
    config,
    configure_logging,
    get_logger,
)

MARKER = "LOCAL-VALUE-7f3a91"
ANSI = re.compile(r"\x1b\[")


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def _restore(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (config.LEVEL_VARIABLE, config.FORMAT_VARIABLE, config.THIRD_PARTY_VARIABLE):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    yield
    for name in (config.LEVEL_VARIABLE, config.FORMAT_VARIABLE, config.THIRD_PARTY_VARIABLE):
        os.environ.pop(name, None)  # monkeypatch restores after this fixture's teardown
    clear_scan_context()
    configure_logging(force=True)


def _lines(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


def _raise_with_local() -> None:
    marker = MARKER
    raise RuntimeError("boom " + str(len(marker)))


# format and keys


def test_json_output_keys_and_utc_timestamp(log_output: io.StringIO) -> None:
    get_logger("t").info("hello_world", n=1)
    raw = log_output.getvalue().strip()
    event = json.loads(raw)
    assert {"event", "level", "logger", "timestamp", "n"} <= set(event)
    assert event["event"] == "hello_world"
    assert event["timestamp"].endswith("Z")
    assert list(event) == sorted(event)


def test_format_autodetection() -> None:
    tty = FakeTTY()
    configure_logging(stream=tty, force=True)
    get_logger("t").info("on_tty")
    assert not tty.getvalue().lstrip().startswith("{")
    plain = io.StringIO()
    configure_logging(stream=plain, force=True)
    get_logger("t").info("not_tty")
    assert json.loads(plain.getvalue())["event"] == "not_tty"


def test_console_colours_and_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    tty = FakeTTY()
    configure_logging(stream=tty, fmt="console", force=True)
    get_logger("t").info("coloured")
    assert ANSI.search(tty.getvalue())
    monkeypatch.setenv("NO_COLOR", "1")
    plain = FakeTTY()
    configure_logging(stream=plain, fmt="console", force=True)
    get_logger("t").info("plain")
    assert "plain" in plain.getvalue()
    assert not ANSI.search(plain.getvalue())


def test_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.LEVEL_VARIABLE, "DEBUG")
    monkeypatch.setenv(config.FORMAT_VARIABLE, "json")
    buffer = FakeTTY()
    configure_logging(stream=buffer, force=True)
    get_logger("t").debug("visible")
    assert _lines(buffer)[0]["event"] == "visible"


def test_argument_beats_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.LEVEL_VARIABLE, "DEBUG")
    monkeypatch.setenv(config.FORMAT_VARIABLE, "console")
    buffer = io.StringIO()
    configure_logging(level="WARNING", fmt="json", stream=buffer, force=True)
    log = get_logger("t")
    log.info("dropped")
    log.warning("kept")
    assert [e["event"] for e in _lines(buffer)] == ["kept"]


@pytest.mark.parametrize(
    ("kwargs", "accepted"), [({"level": "LOUD"}, "DEBUG"), ({"fmt": "xml"}, "json")]
)
def test_invalid_values_raise(kwargs: dict[str, Any], accepted: str) -> None:
    with pytest.raises(ValueError, match=accepted):
        configure_logging(stream=io.StringIO(), force=True, **kwargs)


def test_invalid_environment_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.FORMAT_VARIABLE, "yaml")
    with pytest.raises(ValueError, match="console"):
        configure_logging(stream=io.StringIO(), force=True)


# idempotence and levels


def test_second_call_is_a_no_op(log_output: io.StringIO) -> None:
    configure_logging(fmt="json", stream=io.StringIO())
    root = logging.getLogger()
    ours = [
        h for h in root.handlers if isinstance(h.formatter, structlog.stdlib.ProcessorFormatter)
    ]
    assert len(ours) == 1
    get_logger("t").info("once")
    assert len(_lines(log_output)) == 1


def test_force_reconfigures(log_output: io.StringIO) -> None:
    second = io.StringIO()
    configure_logging(fmt="json", stream=second, force=True)
    get_logger("t").info("moved")
    assert log_output.getvalue() == ""
    assert _lines(second)[0]["event"] == "moved"


def test_level_filtering() -> None:
    buffer = io.StringIO()
    configure_logging(level="INFO", fmt="json", stream=buffer, force=True)
    get_logger("t").debug("hidden")
    assert buffer.getvalue() == ""
    configure_logging(level="DEBUG", fmt="json", stream=buffer, force=True)
    get_logger("t").debug("shown")
    assert _lines(buffer)[0]["event"] == "shown"


# standard library and third parties


def test_stdlib_records_use_the_same_chain(log_output: io.StringIO) -> None:
    logging.getLogger("third.party").warning("x")
    event = _lines(log_output)[0]
    assert event["logger"] == "third.party"
    assert event["level"] == "warning"
    assert event["event"] == "x"


def test_third_party_loggers_are_clamped(log_output: io.StringIO) -> None:
    for name in config.THIRD_PARTY_LOGGERS:
        assert logging.getLogger(name).level == logging.WARNING
    logging.getLogger("httpx").debug("request headers")
    assert log_output.getvalue() == ""


def test_escape_hatch_lifts_clamp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.THIRD_PARTY_VARIABLE, "1")
    buffer = io.StringIO()
    configure_logging(level="DEBUG", fmt="json", stream=buffer, force=True)
    assert logging.getLogger("httpx").level == logging.NOTSET
    events = [e["event"] for e in _lines(buffer)]
    assert "third_party_debug_logging_enabled" in events


# tracebacks


@pytest.mark.parametrize("fmt", ["json", "console"])
def test_tracebacks_never_show_locals(fmt: config.Format) -> None:
    buffer = io.StringIO()
    configure_logging(fmt=fmt, stream=buffer, force=True)
    try:
        _raise_with_local()
    except RuntimeError:
        get_logger("t").exception("stage_failed")
    try:
        _raise_with_local()
    except RuntimeError:
        logging.getLogger("third.party").exception("stdlib_failed")
    output = buffer.getvalue()
    assert "RuntimeError" in output
    assert "boom" in output
    assert MARKER not in output


@pytest.mark.parametrize("fmt", ["json", "console"])
def test_exception_is_data_in_the_redaction_slot(
    fmt: config.Format, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[EventDict] = []

    def spy(logger: WrappedLogger, method: str, event_dict: EventDict) -> EventDict:
        seen.append(dict(event_dict))
        return event_dict

    original = config._formatter_processors

    def with_spy(fmt: config.Format, stream: Any) -> list[Any]:
        processors = original(fmt, stream)
        return [*processors[:-1], spy, processors[-1]]

    monkeypatch.setattr(config, "_formatter_processors", with_spy)
    configure_logging(fmt=fmt, stream=io.StringIO(), force=True)
    for emit in (get_logger("t").exception, logging.getLogger("third.party").exception):
        try:
            _raise_with_local()
        except RuntimeError:
            emit("failed")
    assert len(seen) == 2
    for event in seen:
        assert "exception" in event
        assert "exc_info" not in event


# context


def test_scan_context_binding(log_output: io.StringIO) -> None:
    bind_scan_context(scan_id="scan_1", stage="parse")
    get_logger("t").info("with_context")
    clear_scan_context()
    get_logger("t").info("without_context")
    first, second = _lines(log_output)
    assert first["scan_id"] == "scan_1"
    assert first["stage"] == "parse"
    assert "scan_id" not in second


def test_context_does_not_leak_between_threads(log_output: io.StringIO) -> None:
    def worker(scan_id: str) -> None:
        bind_scan_context(scan_id=scan_id)
        get_logger("t").info("thread_event", worker=scan_id)

    threads = [threading.Thread(target=worker, args=(f"scan_{i}",)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for event in _lines(log_output):
        assert event["scan_id"] == event["worker"]


def test_context_does_not_leak_between_tasks(log_output: io.StringIO) -> None:
    async def task(scan_id: str) -> None:
        bind_scan_context(scan_id=scan_id)
        await asyncio.sleep(0)
        get_logger("t").info("task_event", worker=scan_id)

    async def main() -> None:
        await asyncio.gather(task("scan_a"), task("scan_b"))

    asyncio.run(main())
    events = [e for e in _lines(log_output) if e["event"] == "task_event"]
    assert len(events) == 2
    for event in events:
        assert event["scan_id"] == event["worker"]


# stdout and entry point


def test_nothing_on_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(fmt="json", force=True)
    get_logger("t").warning("to_stderr")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "to_stderr" in captured.err


def test_main_configures_logging_before_run(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(codekavach.cli.app, "configure_logging", lambda: calls.append("configure"))

    def fake_run(command: object, argv: object) -> int:
        calls.append("run")
        return 0

    monkeypatch.setattr(codekavach.cli.app, "run", fake_run)
    assert codekavach.cli.app.main([]) == 0
    assert calls == ["configure", "run"]
