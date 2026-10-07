"""The generated command-line reference (E05-29): walking, rendering, escaping, ``--check``."""

import importlib.util
import re
import sys
from enum import StrEnum
from pathlib import Path
from types import ModuleType
from typing import Annotated

import pytest
import typer
import typer.main
from typer import _click as click

from codekavach.cli.app import build_cli
from tests.support.golden import assert_matches_golden

REPO_ROOT = Path(__file__).resolve().parents[3]
PAGE = REPO_ROOT / "docs" / "reference" / "cli.md"
GOLDEN = Path(__file__).parent / "data" / "gen_cli_docs_synthetic.md"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_cli_docs", REPO_ROOT / "tools" / "gen_cli_docs.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_cli_docs"] = module
    spec.loader.exec_module(module)
    return module


gen = _load()


class Colour(StrEnum):
    RED = "red"
    BLUE = "blue"


def synthetic() -> click.Command:
    """A small tree: a nested group, a hidden command, a flag pair, a choice, a repeatable
    option, a required option, a range, a secret-looking default and an argument."""
    app = typer.Typer(help="A synthetic tool.", no_args_is_help=True)
    nested = typer.Typer(help="Nested commands.")
    app.add_typer(nested, name="nested")

    @app.command("run")
    def run(  # noqa: PLR0917 - Typer maps each parameter to one option
        target: Annotated[str, typer.Argument(help="What to run <TARGET> on.")] = ".",
        issues: Annotated[bool, typer.Option("--issues/--no-issues", help="Create issues.")] = True,
        colour: Annotated[Colour, typer.Option(help="The colour.")] = Colour.RED,
        include: Annotated[list[str] | None, typer.Option(help="A glob; repeat. A | B.")] = None,
        name: Annotated[str, typer.Option(help="Required name.")] = ...,
        jobs: Annotated[int, typer.Option(min=1, max=64, help="Workers.")] = 4,
        api_token: Annotated[str, typer.Option(help="A token.")] = "x",  # noqa: S107
    ) -> None:
        """Run the thing.

        A second paragraph with [bold]markup[/bold] and <SECRET:aws_access_key:1>.
        """

    @app.command("secret-plumbing", hidden=True)
    def hidden() -> None:
        """Not for the reference."""

    @nested.command("deep")
    def deep(path: Annotated[Path, typer.Option(help="A path.")] = Path("out")) -> None:
        """Go deeper."""

    del run, hidden, deep
    return typer.main.get_command(app)


# --- walking -------------------------------------------------------------------------------------


def test_iter_commands_is_depth_first_sorted_and_skips_hidden() -> None:
    paths = [path for path, _ in gen.iter_commands(synthetic())]
    assert paths == [(), ("nested",), ("nested", "deep"), ("run",)]


def test_the_real_tree_is_walked_completely() -> None:
    paths = [path for path, _ in gen.iter_commands(build_cli())]
    assert () in paths and ("config", "key", "set") in paths and ("plugins", "check") in paths
    assert paths == sorted(paths) or paths[0] == ()  # children come in name order
    assert len(paths) == len(set(paths))


# --- rendering -----------------------------------------------------------------------------------


def section(path: tuple[str, ...]) -> str:
    command = dict(gen.iter_commands(synthetic()))[path]
    return str(gen.render_command(path, command))


def test_a_section_matches_its_golden_file() -> None:
    text = section(("run",))
    assert_matches_golden(text, GOLDEN)


def test_types_defaults_and_flags() -> None:
    text = section(("run",))
    assert "| `--issues / --no-issues` | flag | on | Create issues. |" in text
    assert "| `--colour` | red \\| blue | red | The colour. |" in text
    assert "| `--include` | TEXT (repeatable) |  | A glob; repeat. A \\| B. |" in text
    assert "| `--name` | TEXT | required | Required name. |" in text
    assert "| `--jobs` | INTEGER 1..64 | 4 | Workers. |" in text
    assert "| `--api-token` | TEXT | (dynamic) | A token. |" in text  # a secret-looking default
    assert "| `TARGET` | TEXT | . | What to run `<TARGET>` on. |" in text


def test_markup_and_angle_brackets_in_the_help() -> None:
    text = section(("run",))
    assert "A second paragraph with markup and `<SECRET:aws_access_key:1>`." in text
    assert "[bold]" not in text


def test_a_group_section_points_at_its_sub_commands() -> None:
    text = section(("nested",))
    assert "Run a sub-command with `--help` for its options." in text
    assert text.rstrip().endswith("Global options apply.")


def test_usage_is_one_line_at_a_fixed_width() -> None:
    command = dict(gen.iter_commands(synthetic()))[("run",)]
    assert gen.usage_of(("run",), command) == "Usage: codekavach run [OPTIONS] [target]"


def test_a_path_default_has_no_absolute_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert gen.relative(str(tmp_path / "out" / "x")) == "out/x"  # forward slashes everywhere
    assert gen.relative(str(tmp_path)) == "."
    assert gen.relative(str(Path.home() / "reports")) == "~/reports"
    assert gen.relative("out/x") == "out/x"
    assert gen.relative("out\\x") == "out/x"


# --- escaping -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a | b", "a \\| b"),
        ("<SECRET:aws_access_key:1>", "`<SECRET:aws_access_key:1>`"),
        ("already `<x>` fine", "already `<x>` fine"),
        ("[bold]loud[/bold] text", "loud text"),
        ("[SCAN_ID|latest]", "[SCAN_ID\\|latest]"),
        ("two\nlines  here", "two lines here"),
        ("\x1b[31mred\x1b[0m", "red"),
    ],
)
def test_escape_cell(text: str, expected: str) -> None:
    assert gen.escape_cell(text) == expected


def test_paragraphs_survive_reflow() -> None:
    assert gen.escape_paragraph("One\nline.\n\nSecond   paragraph <x>.") == (
        "One line.\n\nSecond paragraph `<x>`."
    )
    assert gen.plain(None) == "" and gen.plain("") == ""


def test_anchors_follow_the_github_rule() -> None:
    assert gen.anchor(("privacy", "ledger", "verify")) == "codekavach-privacy-ledger-verify"
    assert gen.anchor(()) == "codekavach"


# --- --check ------------------------------------------------------------------------------------


def test_check_returns_zero_one_and_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "cli.md"
    assert gen.main(["--check", "--out", str(out)]) == 2
    assert "missing" in capsys.readouterr().err
    assert gen.main(["--out", str(out)]) == 0
    assert gen.main(["--check", "--out", str(out)]) == 0
    out.write_text(
        out.read_text(encoding="utf-8").replace("Scan a code base", "Look at code"), "utf-8"
    )
    assert gen.main(["--check", "--out", str(out)]) == 1
    err = capsys.readouterr().err
    assert "-Look at code" in err and "+Scan a code base" in err
    assert "tools/gen_cli_docs.py" in err
    assert len(err.splitlines()) <= gen.DIFF_LINES + 3


def test_writing_twice_is_byte_identical(tmp_path: Path) -> None:
    one, two = tmp_path / "one.md", tmp_path / "two.md"
    gen.main(["--out", str(one)])
    gen.main(["--out", str(two)])
    assert one.read_bytes() == two.read_bytes()
    assert b"\r" not in one.read_bytes()


# --- the real page -------------------------------------------------------------------------------


def test_the_committed_page_is_current() -> None:
    assert gen.main(["--check"]) == 0


def test_every_visible_command_has_a_heading() -> None:
    text = PAGE.read_text(encoding="utf-8")
    headings = set(re.findall(r"^## (codekavach.*)$", text, flags=re.MULTILINE))
    expected = {gen.heading(path) for path, _ in gen.iter_commands(build_cli())}
    assert expected <= headings
    assert "## Global options" in text and "## Exit codes" in text


def test_the_page_has_the_global_options_and_the_exit_codes() -> None:
    text = PAGE.read_text(encoding="utf-8")
    for option in ("--config", "--profile", "--privacy-level", "--offline", "--json", "--quiet"):
        assert f"`{option}`" in text
    for line in ("0    OK", "2    USAGE", "3    PRIVACY_BLOCK", "130  CANCELLED"):
        assert line in text
    assert gen.NOTICE in text
    assert gen.NOTICE.startswith("This page is produced by tools/gen_cli_docs.py")


def test_the_page_has_no_path_escape_or_markup() -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert "\x1b" not in text
    assert not re.search(r"\[/?(bold|dim|italic|cyan|red|green|yellow)\]", text)
    assert str(Path.home()) not in text
    assert not re.search(r"[A-Za-z]:\\\\|/Users/|/home/", text)


def test_the_page_is_linked_from_the_readme_and_the_exit_code_page() -> None:
    assert "docs/reference/cli.md" in (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "cli.md" in (REPO_ROOT / "docs" / "reference" / "exit-codes.md").read_text(
        encoding="utf-8"
    )


def test_ci_and_pre_commit_run_the_check() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    hooks = (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "tools/gen_cli_docs.py --check" in workflow
    assert "tools/gen_cli_docs.py --check" in hooks
    assert "pass_filenames: false" in hooks.split("tools/gen_cli_docs.py --check", 1)[1][:200]
