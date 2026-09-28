import enum
import io
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import typer
from hypothesis import given
from hypothesis import strategies as st
from rich.console import Console
from tools.export_cli_schema import SCHEMA_PATH
from tools.export_cli_schema import render as render_schema

from codekavach.cli.app import app
from codekavach.cli.errors import UsageError
from codekavach.cli.output import (
    Envelope,
    Output,
    get_output,
    kv_table,
    severity_style,
    simple_table,
    status_text,
    to_jsonable,
)
from codekavach.core.models.text import RawCode, SanitisedText
from tests.support.cli import CLI_TEST_WIDTH, CliResult, assert_no_ansi
from tests.support.golden import assert_matches_golden

Cli = Callable[..., CliResult]
GOLDEN = Path(__file__).parent / "golden"
KEYS = {"schema_version", "codekavach_version", "command", "ok", "exit_code", "data",
        "warnings", "errors"}  # fmt: skip
ACTION: dict[str, Any] = {}


@pytest.fixture
def demo() -> Iterator[None]:
    """``demo`` and ``nested ledger verify`` commands that use the output layer."""

    def demo_command(ctx: typer.Context) -> None:
        out = get_output(ctx)
        out.info("working")
        out.warn("slow_disk", "the disk is slow", hint="use an SSD")
        if ACTION.get("raise"):
            raise ACTION["raise"]
        out.result({"n": 1})
        if ACTION.get("finish_twice"):
            out.finish(0)
            out.finish(0)

    privacy = typer.Typer()
    ledger = typer.Typer()

    @ledger.command("verify")
    def verify(ctx: typer.Context) -> None:
        get_output(ctx).result({"verified": True})

    privacy.add_typer(ledger, name="ledger")
    app.command("demo")(demo_command)
    app.add_typer(privacy, name="nested")
    try:
        yield
    finally:
        app.registered_commands[:] = [c for c in app.registered_commands if c.name != "demo"]
        app.registered_groups[:] = [g for g in app.registered_groups if g.name != "nested"]
        ACTION.clear()


def test_human_mode(cli: Cli, demo: None) -> None:
    result = cli(["demo"])
    assert result.exit_code == 0
    assert "working" in result.stderr
    assert "warning[slow_disk]: the disk is slow" in result.stderr
    assert "hint: use an SSD" in result.stderr
    assert "n" in result.stdout
    assert "working" not in result.stdout


def test_quiet_drops_info_only(cli: Cli, demo: None) -> None:
    result = cli(["demo", "--quiet"])
    assert "working" not in result.stderr
    assert "warning[slow_disk]" in result.stderr
    assert "1" in result.stdout


def test_json_mode(cli: Cli, demo: None) -> None:
    result = cli(["demo", "--json"])
    assert result.exit_code == 0
    assert result.stdout.count("\n") == 1
    assert_no_ansi(result.stdout)
    envelope = result.json
    assert set(envelope) == KEYS
    assert (envelope["command"], envelope["ok"], envelope["data"]) == ("demo", True, {"n": 1})
    assert envelope["warnings"] == [
        {"code": "slow_disk", "message": "the disk is slow", "hint": "use an SSD"}
    ]
    assert "working" not in result.stderr


def test_json_error(cli: Cli, demo: None) -> None:
    ACTION["raise"] = UsageError("bad", code="bad_input", hint="fix it")
    result = cli(["--json", "demo"])
    assert result.exit_code == 2
    envelope = result.json
    assert (envelope["ok"], envelope["exit_code"]) == (False, 2)
    assert envelope["errors"] == [{"code": "bad_input", "message": "bad", "hint": "fix it"}]


def test_json_usage_error(cli: Cli, demo: None) -> None:
    result = cli(["--json", "demo", "--nope"])
    assert result.exit_code == 2
    envelope = result.json
    assert envelope["command"] == "demo"
    assert envelope["errors"][0]["code"] == "usage"


def test_json_internal_error_hides_message(cli: Cli, demo: None) -> None:
    ACTION["raise"] = RuntimeError("SECRETVALUE")
    result = cli(["demo", "--json"])
    assert result.exit_code == 4
    assert "SECRETVALUE" not in result.stdout
    assert result.json["errors"][0]["code"] == "internal"


def test_envelope_written_once(cli: Cli, demo: None) -> None:
    ACTION["finish_twice"] = True
    result = cli(["demo", "--json"])
    assert result.stdout.count("\n") == 1
    assert result.json["exit_code"] == 0


def test_nested_command_path(cli: Cli, demo: None) -> None:
    result = cli(["nested", "ledger", "verify", "--json"])
    assert result.json["command"] == "nested ledger verify"
    assert result.json["data"] == {"verified": True}


def test_output_error_method(capsys: pytest.CaptureFixture[str]) -> None:
    human = Output(json_mode=False, quiet=True, command="x")
    human.error(UsageError("nope", code="bad_input"))
    assert "error[bad_input]: nope" in capsys.readouterr().err
    machine = Output(json_mode=True, quiet=False, command="x")
    machine.error(ValueError("secret"))
    machine.finish(4)
    machine.finish(4)
    written = capsys.readouterr().out
    assert written.count("\n") == 1
    assert json.loads(written)["errors"][0]["code"] == "internal"


class Colour(enum.Enum):
    RED = "red"


@dataclass
class Point:
    x: int
    where: Path


def test_to_jsonable_values() -> None:
    moment = datetime(2026, 9, 24, 10, 0, tzinfo=UTC)
    assert to_jsonable(
        {"e": Colour.RED, "p": Path("a/b"), "t": moment, "s": {3, 1}, "d": Point(1, Path("x"))}
    ) == {"e": "red", "p": str(Path("a/b")), "t": "2026-09-24T10:00:00Z", "s": [1, 3],
          "d": {"x": 1, "where": "x"}}  # fmt: skip


class FakeVaultEntry:
    pass


FakeVaultEntry.__module__ = "codekavach.privacy.vault.store"


@pytest.mark.parametrize(
    "value",
    [RawCode("x"), {"a": [SanitisedText("y")]}, FakeVaultEntry(), [1, {"k": (RawCode("z"),)}]],
)
def test_guard(value: object) -> None:
    with pytest.raises(TypeError, match="refusing to serialise"):
        to_jsonable(value)


def test_sanitised_on_request() -> None:
    assert to_jsonable(SanitisedText("y"), allow_sanitised=True) == "y"
    with pytest.raises(TypeError):
        to_jsonable(object())


leaves = (
    st.none() | st.booleans() | st.integers() | st.text(max_size=5)
    | st.sampled_from(list(Colour)) | st.builds(Path, st.text("abc", min_size=1, max_size=3))
    | st.datetimes(timezones=st.just(UTC))
)  # fmt: skip
trees = st.recursive(
    leaves,
    lambda children: (
        st.lists(children, max_size=3)
        | st.dictionaries(st.text(max_size=3), children, max_size=3)
        | st.lists(children, max_size=3).map(tuple)
    ),
    max_leaves=12,
)


@given(trees, st.integers(0, 5))
def test_property_serialisable_and_guarded(tree: Any, position: int) -> None:
    json.loads(json.dumps(to_jsonable(tree)))
    poisoned = [tree] * position + [RawCode("secret")] + [tree]
    with pytest.raises(TypeError):
        to_jsonable({"nested": poisoned})


def render(renderable: Any) -> str:
    buffer = io.StringIO()
    Console(file=buffer, width=CLI_TEST_WIDTH, color_system=None, legacy_windows=False).print(
        renderable
    )
    return buffer.getvalue()


def test_tables_golden() -> None:
    text = render(kv_table("Settings", [("privacy.level", "L3"), ("llm.provider", "mock")]))
    text += render(simple_table(["Check", "Status"], [["grammar:python", "PASS"]]))
    text += render(status_text("fail")) + severity_style("HIGH") + "\n"
    assert_matches_golden(text, GOLDEN / "output_tables.txt")


def test_envelope_golden() -> None:
    output = Output(json_mode=True, quiet=False, command="doctor")
    output.result({"checks": [{"name": "grammar:python", "status": "fail"}]})
    envelope = output.envelope(1).model_dump(mode="json")
    envelope["codekavach_version"] = "0.0.0"
    assert_matches_golden(json.dumps(envelope, indent=2) + "\n", GOLDEN / "envelope.json")


def test_schema_has_not_drifted() -> None:
    assert SCHEMA_PATH.read_text(encoding="utf-8") == render_schema()
    assert Envelope.model_json_schema()["title"] == "Envelope"
