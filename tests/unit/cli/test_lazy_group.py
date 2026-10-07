"""The lazily resolved root group (E05-31)."""

import inspect
import json
import subprocess
import sys

import pytest
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli import app as app_module
from codekavach.cli.app import LAZY_COMMANDS, LazyEntry, LazyGroup, build_cli
from tests.support.cli import run_cli

ORDER = ["version", "scan", "report", "doctor", "completion", "init", "privacy", "providers",
         "plugins", "vault", "config"]  # fmt: skip


def root() -> LazyGroup:
    command = build_cli()
    assert isinstance(command, LazyGroup)
    return command


def test_list_commands_keeps_the_order() -> None:
    group = root()
    assert group.list_commands(click.Context(group)) == ORDER


def test_unknown_name_is_none() -> None:
    group = root()
    assert group.get_command(click.Context(group), "no-such-command") is None


def test_placeholders_while_listing_and_real_commands_otherwise() -> None:
    group = root()
    listing = click.Context(group, resilient_parsing=True)
    placeholder = group.get_command(listing, "scan")
    assert placeholder is not None
    assert placeholder.params == []
    real = group.get_command(click.Context(group), "scan")
    assert real is not None
    names = {param.name for param in real.params}
    assert {"fail_on", "json_mode", "privacy_level"} <= names  # own and global options


def test_get_command_imports_on_first_use_only() -> None:
    program = (
        "import json, sys\n"
        "from typer import _click as click\n"
        "from codekavach.cli.app import build_cli\n"
        "group = build_cli()\n"
        "group.list_commands(click.Context(group))\n"
        "before = 'codekavach.cli.vault' in sys.modules\n"
        "group.get_command(click.Context(group), 'vault')\n"
        "print(json.dumps([before, 'codekavach.cli.vault' in sys.modules]))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=True
    ).stdout
    assert json.loads(out.strip().splitlines()[-1]) == [False, True]


def test_broken_target_names_the_command() -> None:
    group = root()
    broken = LazyEntry("broken", "codekavach.cli.does_not_exist:thing", "command", "Broken.")
    with pytest.raises(click.ClickException, match="command 'broken' is not available"):
        group.resolve_lazy(broken)


def first_paragraph(text: str) -> str:
    return " ".join(inspect.cleandoc(text).split("\n\n", 1)[0].split())


@pytest.mark.parametrize("entry", LAZY_COMMANDS, ids=[entry.name for entry in LAZY_COMMANDS])
def test_short_help_matches_the_real_command(entry: LazyEntry) -> None:
    group = root()
    real = group.resolve_lazy(entry)
    help_text = real.short_help or real.help or ""
    assert entry.short_help == first_paragraph(help_text)
    assert (entry.kind == "group") == hasattr(real, "commands")


def test_global_options_on_lazy_commands() -> None:
    result = run_cli(["doctor", "--json"])
    assert result.stdout.lstrip().startswith("{")
    assert json.loads(result.stdout)["command"] == "doctor"


def test_root_app_is_recorded_for_command_building() -> None:
    build_cli()
    assert app_module.RootGroup.root_app is app_module.app
