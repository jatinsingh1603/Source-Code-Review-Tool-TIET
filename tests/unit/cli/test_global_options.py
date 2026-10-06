import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Annotated, Any

import pytest
import typer
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click
from typer.core import TyperGroup

from codekavach.cli import context as context_module
from codekavach.cli.app import app, build_cli
from codekavach.cli.context import CliContext, get_context, with_target
from codekavach.cli.options import attach_global_options
from tests.support.cli import CliResult

Cli = Callable[..., CliResult]
SEEN: dict[str, Any] = {}


@pytest.fixture
def probe() -> Iterator[None]:
    """A temporary ``probe`` command that records its ``CliContext``."""

    def command(ctx: typer.Context) -> None:
        SEEN["context"] = get_context(ctx)
        if SEEN.get("load"):
            SEEN["loaded"] = get_context(ctx).loaded

    app.command("probe")(command)
    try:
        yield
    finally:
        app.registered_commands[:] = [c for c in app.registered_commands if c.name != "probe"]
        SEEN.clear()


def context() -> CliContext:
    found = SEEN["context"]
    assert isinstance(found, CliContext)
    return found


FLAGS = {
    "--json": "json_mode",
    "--offline": "offline",
    "--debug": "debug",
    "--no-user-config": "use_user_config",
    "--trust-project-config": "trust_project_config",
    "--quiet": "quiet",
}


def flag_value(ctx: CliContext, flag: str) -> bool:
    value = getattr(ctx, FLAGS[flag])
    return not value if flag == "--no-user-config" else bool(value)


@pytest.mark.parametrize("flag", sorted(FLAGS))
@pytest.mark.parametrize("before", [True, False])
def test_both_positions(cli: Cli, probe: None, flag: str, before: bool) -> None:
    result = cli([flag, "probe"] if before else ["probe", flag])
    assert result.exit_code == 0, result.stderr
    assert flag_value(context(), flag)


@pytest.mark.parametrize("before", [True, False])
def test_valued_options(cli: Cli, probe: None, before: bool, tmp_path: Path) -> None:
    config = tmp_path / "ck.toml"
    config.write_text("")
    options = ["--profile", "ci", "--provider", "mock", "--model", "m", "--config", str(config),
               "--privacy-level", "l2", "-vv", "--set", "scan.jobs=3"]  # fmt: skip
    cli([*options, "probe"] if before else ["probe", *options])
    ctx = context()
    assert (ctx.profile, ctx.provider, ctx.model, ctx.config_file, ctx.verbosity) == (
        "ci", "mock", "m", config, 2,
    )  # fmt: skip
    assert ctx.cli_overrides.data == {
        "privacy": {"level": "L2"},
        "llm": {"default_provider": "mock", "model": "m"},
        "scan": {"jobs": 3},
    }
    assert ctx.argv_origin["privacy.level"] == "--privacy-level"


def test_later_position_wins_and_defaults_do_not_erase(cli: Cli, probe: None) -> None:
    cli(["--provider", "a", "probe", "--provider", "b"])
    assert context().provider == "b"
    cli(["--json", "probe"])
    assert context().json_mode is True
    cli(["--set", "scan.jobs=2", "probe", "--set", "privacy.level=L4"])
    assert context().cli_overrides.data == {"scan": {"jobs": 2}, "privacy": {"level": "L4"}}


def test_option_environment_variables(cli: Cli, probe: None) -> None:
    cli(["probe"], env={"CODEKAVACH_JSON": "1", "CODEKAVACH_PROVIDER": "mock"})
    assert context().json_mode is True
    assert context().provider == "mock"


def test_overrides_for_privacy_and_provider(
    cli: Cli, probe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_load(**kwargs: Any) -> Any:
        captured.update(kwargs)
        raise RuntimeError("stop after capturing")

    monkeypatch.setattr(context_module, "load_settings", fake_load)
    SEEN["load"] = True
    cli(["probe", "--privacy-level", "L2", "--provider", "mock"])
    assert captured["cli_overrides"].data == {
        "privacy": {"level": "L2"},
        "llm": {"default_provider": "mock"},
    }


def test_offline_overrides(cli: Cli, probe: None) -> None:
    cli(["probe", "--offline"])
    data = context().cli_overrides.data
    assert data["llm"] == {"allow_remote": False}
    assert "privacy" not in data


def test_conflicts(cli: Cli, probe: None, project_dir: Path) -> None:
    SEEN["load"] = True
    result = cli(["probe", "--model", "x"], cwd=project_dir)
    assert result.exit_code == 2
    assert "error[model_needs_provider]" in result.stderr
    (project_dir / "codekavach.toml").write_text(
        '[llm.providers.cloud]\nkind = "openai"\nmodel = "m"\n'
    )
    # A provider defined in the project file needs a trusted project (E03-25).
    result = cli(
        ["probe", "--offline", "--provider", "cloud", "--trust-project-config"], cwd=project_dir
    )
    assert result.exit_code == 2
    # The loader's semantic rule (E03-23) reports this before the CLI's own check can.
    assert "error[CK-CFG-031]" in result.stderr
    assert "--> --offline" in result.stderr
    result = cli(["probe", "-q", "-v"])
    assert result.exit_code == 2
    assert "error[quiet_verbose_conflict]" in result.stderr
    offline_mock = ["probe", "--offline", "--provider", "mock", "--trust-project-config"]
    assert cli(offline_mock, cwd=project_dir).exit_code == 0


def test_invalid_values(cli: Cli, probe: None) -> None:
    assert cli(["probe", "--privacy-level", "L9"]).exit_code == 2
    assert cli(["probe", "--config", "missing.toml"]).exit_code == 2


def test_help_and_version_do_not_load(
    cli: Cli, probe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(**kwargs: Any) -> Any:
        raise AssertionError("configuration read")

    monkeypatch.setattr(context_module, "load_settings", refuse)
    assert cli(["--help"]).exit_code == 0
    assert cli(["probe", "--help"]).exit_code == 0
    assert cli(["--version"]).exit_code == 0
    assert cli(["probe", "--json"]).exit_code == 0


def test_command_declaration_wins() -> None:
    sub = typer.Typer()

    @sub.command()
    def own(json: Annotated[bool, typer.Option("--json")] = False) -> None:
        typer.echo(json)

    command = typer.main.get_command(sub)
    attach_global_options(command)
    attach_global_options(command)
    names = [param.name for param in command.params]
    assert names.count("json") == 1
    assert "json_mode" not in names


def test_with_target(cli: Cli, probe: None, tmp_path: Path) -> None:
    captured: list[CliContext] = []

    def command(ctx: typer.Context) -> None:
        captured.append(with_target(ctx, tmp_path))
        captured.append(get_context(ctx))

    app.command("target-probe")(command)
    try:
        cli(["target-probe"])
    finally:
        app.registered_commands[:] = [
            c for c in app.registered_commands if c.name != "target-probe"
        ]
    assert captured[0].target_hint == tmp_path
    assert captured[1] is captured[0]


def test_every_command_has_the_options() -> None:
    command = build_cli()
    assert isinstance(command, TyperGroup)
    ctx = click.Context(command)
    children = [command.get_command(ctx, name) for name in command.list_commands(ctx)]
    assert len(children) >= 9  # resolves the lazily mounted commands (E05-31)
    for target in (command, *(child for child in children if child is not None)):
        names = {param.name for param in target.params}
        assert {"json_mode", "offline", "set_values", "verbose"} <= names


BOOLEAN = ["--json", "--offline", "--debug", "--trust-project-config"]


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=40)
@given(
    chosen=st.lists(st.sampled_from(BOOLEAN), unique=True),
    positions=st.lists(st.booleans(), min_size=4, max_size=4),
)
def test_property_boolean_flags(
    cli: Cli, probe: None, chosen: list[str], positions: list[bool]
) -> None:
    before = [flag for flag, first in zip(chosen, positions, strict=False) if first]
    after = [flag for flag, first in zip(chosen, positions, strict=False) if not first]
    result = cli([*before, "probe", *after])
    assert result.exit_code == 0
    ctx = context()
    for flag in BOOLEAN:
        assert flag_value(ctx, flag) is (flag in chosen)
    json.dumps(sorted(chosen))
