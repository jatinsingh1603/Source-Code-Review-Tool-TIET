"""The CLI user guide is held to the command tree and to the contracts it describes (E05-33).

``docs/guide/cli.md`` is task-oriented prose that people copy commands from, so it must not drift
from the tool:

- every ``$ codekavach ...`` line of a ``console`` block, and every ``codekavach ...`` line of a
  ``yaml`` block, names a command path that exists and long and short options that the command (or
  the global options) has, and every command path answers ``--help``;
- the table "What this build can do" is compared with what the commands do now, so it changes when
  a back end lands;
- the two CI examples are valid YAML with pinned actions, and their shell is run against a stub
  ``codekavach`` for each exit code, so the reporting of code 4 is distinct from codes 1 and 3;
- the configuration shown holds a reference to a secret and loads as settings;
- the ten sections, the four scope statements and the residual-disclosure sentence of the privacy
  notice are present, no URL other than the project repository is cited, and no claim word of
  ``AGENTS.md`` section 9 is left unexplained.
"""

import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer import _click as click  # the Click copy that Typer's commands use
from typer.core import TyperGroup

from codekavach.cli.app import build_cli
from codekavach.cli.onboarding import MEASURED_LINE
from codekavach.config import Settings
from tests.support.cli_fixtures import Cli

REPO_ROOT = Path(__file__).resolve().parents[2]
GUIDE = REPO_ROOT / "docs" / "guide" / "cli.md"
TEXT = GUIDE.read_text(encoding="utf-8")
PROJECT_URL = "https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET"
TITLES = (
    "Install and check your setup",
    "First scan without any API key",
    "See exactly what would be sent",
    "Choosing a privacy level and a provider",
    "Working offline",
    "Reports",
    "CI pipelines",
    "Machine-readable output",
    "Housekeeping",
    "Troubleshooting",
)
SCOPE_STATEMENTS = (
    "It does not fix code and does not open pull requests.",
    "The evidence in a report is text snippets from the code",
    "the ledger shows what would have been sent. Nothing was transmitted.",
    "does not measure structural leakage",
)
# The words of AGENTS.md section 9 item 2. A hit is allowed only as a phrase of this list, each
# with the named test that enforces the design rule it states; the guide has none today.
CLAIM_WORDS = re.compile("never|guarantee|ensures|impossible|100%|best", re.IGNORECASE)
ALLOWED_PHRASES: tuple[str, ...] = ()
# Groups and commands whose bare name stands for a command that can be run.
PROBES: dict[str, list[str]] = {
    "privacy consent": ["privacy", "consent", "status"],
    "config": ["config", "validate"],
    "completion": ["completion", "bash"],
    "init": ["init", "--stdout"],
    "scan": ["scan", "."],
}
BASH = None if sys.platform == "win32" else shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="needs bash, and a POSIX shell is assumed")


@dataclass(frozen=True)
class Block:
    """One fenced block: its info string, the line of its opening fence and its lines."""

    info: str
    first_line: int
    lines: tuple[str, ...]


def blocks(text: str) -> list[Block]:
    found: list[Block] = []
    current: list[str] | None = None
    info, start = "", 0
    for number, line in enumerate(text.splitlines(), start=1):
        if current is None:
            if line.startswith("```"):
                current, info, start = [], line[3:].strip(), number
        elif line.startswith("```"):
            found.append(Block(info, start, tuple(current)))
            current = None
        else:
            current.append(line)
    return found


def command_lines() -> list[tuple[int, str]]:
    """``(line number, command line)`` for each ``codekavach`` command the guide shows."""
    found: list[tuple[int, str]] = []
    for block in blocks(TEXT):
        for offset, line in enumerate(block.lines, start=1):
            if block.info == "console" and line.startswith("$ codekavach "):
                found.append((block.first_line + offset, line[2:]))
            elif block.info == "yaml" and line.strip().startswith("codekavach "):
                found.append((block.first_line + offset, line.strip()))
    return found


def words(command_line: str) -> list[str]:
    """The words of ``codekavach ...`` up to the first shell operator, without the program."""
    lexer = shlex.shlex(command_line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    found: list[str] = []
    for token in lexer:
        if set(token) <= set(lexer.punctuation_chars):
            break
        found.append(token)
    return found[1:]


def option_of(name: str, *commands: click.Command) -> click.Parameter | None:
    for command in commands:
        for param in command.params:
            if name in (*param.opts, *param.secondary_opts):
                return param
    return None


def takes_value(param: click.Parameter) -> bool:
    """Whether the option is followed by a value; a flag or a counter is not."""
    if getattr(param, "param_type_name", None) != "option":
        return False
    return not (getattr(param, "is_flag", False) or getattr(param, "count", False))


def resolve(tokens: Sequence[str]) -> tuple[tuple[str, ...], list[str]]:
    """The command path of ``tokens`` and the options that the command does not have."""
    root = build_cli()
    command: click.Command = root
    path: list[str] = []
    missing: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-") and token != "-":
            name, _, inline = token.partition("=")
            param = option_of(name, command, root)
            if param is None:
                missing.append(name)
            elif not inline and takes_value(param):
                index += 1
        elif isinstance(command, TyperGroup):
            child = command.get_command(click.Context(command), token)
            if child is not None:
                command = child
                path.append(token)
        index += 1
    return tuple(path), missing


COMMANDS = command_lines()
PATHS = sorted({resolve(words(line))[0] for _, line in COMMANDS})


def test_the_guide_shows_commands() -> None:
    assert len(COMMANDS) >= 20  # a parser that finds nothing would pass every test below
    assert any(line.startswith("scan .") for line in (" ".join(words(c)) for _, c in COMMANDS))


@pytest.mark.parametrize(("number", "line"), COMMANDS, ids=[f"line{n}" for n, _ in COMMANDS])
def test_every_command_of_the_guide_exists_with_its_options(number: int, line: str) -> None:
    path, missing = resolve(words(line))
    assert path, f"guide line {number}: {line!r} names no command"
    assert not missing, f"guide line {number}: {' '.join(path)} has no option {missing}"


@pytest.mark.parametrize("path", PATHS, ids=" ".join)
def test_every_command_path_of_the_guide_answers_help(cli: Cli, path: tuple[str, ...]) -> None:
    result = cli([*path, "--help"])
    assert result.exit_code == 0, result.stderr


def test_the_resolver_finds_a_missing_option_and_a_missing_command() -> None:
    assert resolve(["scan", ".", "--no-such-option"]) == (("scan",), ["--no-such-option"])
    assert resolve(["no-such-command"]) == ((), [])
    assert resolve(["--offline", "scan", "--fail-on", "high", "-q"]) == (("scan",), [])
    assert words("codekavach scan . --json > result.json; code=$?") == ["scan", ".", "--json"]


def section_text(title: str) -> str:
    match = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)", TEXT, re.MULTILINE | re.DOTALL)
    assert match is not None, title
    return match.group(1)


def test_the_guide_has_the_ten_sections_in_order() -> None:
    found = re.findall(r"^## (\d+) (.+)$", TEXT, re.MULTILINE)
    assert found == [(str(number), title) for number, title in enumerate(TITLES, start=1)]


def test_the_scope_statements_and_the_notice_sentence_are_present() -> None:
    for statement in SCOPE_STATEMENTS:
        assert statement in TEXT, statement
    assert MEASURED_LINE in section_text("3 See exactly what would be sent")


def probe(command: str) -> list[str]:
    return PROBES.get(command, command.split())


def build_table() -> list[tuple[str, str, str]]:
    """``(command, state, epic)`` for each command of the table 'What this build can do'."""
    rows: list[tuple[str, str, str]] = []
    for line in section_text("What this build can do").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if line.startswith("|") and len(cells) == 3 and cells[1] in {"yes", "not in this build"}:
            rows += [(name, cells[1], cells[2]) for name in re.findall(r"`([^`]+)`", cells[0])]
    return rows


TABLE = build_table()


def test_the_table_covers_every_command_that_needs_a_back_end() -> None:
    assert {name for name, state, _ in TABLE if state != "yes"} == {
        "privacy inspect",
        "privacy ledger show",
        "privacy ledger verify",
        "providers test",
        "report",
        "vault status",
        "vault rotate",
        "vault destroy",
        "demo",
    }


@pytest.mark.parametrize(("command", "state", "epic"), TABLE, ids=[row[0] for row in TABLE])
def test_the_table_says_what_the_command_does_today(
    cli: Cli, project_dir: Path, command: str, state: str, epic: str
) -> None:
    (project_dir / ".git").mkdir()
    assert cli(["scan", "."], cwd=project_dir).exit_code == 0  # the commands read a stored scan
    result = cli(probe(command), cwd=project_dir)
    if state == "yes":
        assert "backend_unavailable" not in result.stderr, (
            f"{command}: the back end is in this build now; change its row in the table of "
            "docs/guide/cli.md and the sections that say it is missing"
        )
        return
    assert result.exit_code == 2, result.stderr
    assert "error[backend_unavailable]" in result.stderr
    assert f"epic {epic}" in result.stderr, (
        f"{command}: the hint names another epic; update the table of docs/guide/cli.md"
    )


def yaml_documents() -> list[Any]:
    return [yaml.safe_load("\n".join(b.lines)) for b in blocks(TEXT) if b.info == "yaml"]


def github_steps() -> list[dict[str, Any]]:
    job = next(doc for doc in yaml_documents() if isinstance(doc, dict) and "jobs" in doc)
    steps: list[dict[str, Any]] = job["jobs"]["review"]["steps"]
    return steps


def gitlab_job() -> dict[str, Any]:
    job = next(doc for doc in yaml_documents() if isinstance(doc, dict) and "codekavach" in doc)
    found: dict[str, Any] = job["codekavach"]
    return found


def test_the_github_example_pins_its_actions_and_uploads_the_reports_always() -> None:
    steps = github_steps()
    uses = [step["uses"] for step in steps if "uses" in step]
    assert uses, "no action is used"
    for action in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action), f"{action} is not pinned"
    upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload"))
    assert upload["if"] == "always()"
    assert "codekavach-report/" in upload["with"]["path"]
    assert "result.json" in upload["with"]["path"]


def test_the_gitlab_example_uploads_the_reports_always() -> None:
    artifacts = gitlab_job()["artifacts"]
    assert artifacts["when"] == "always"
    assert artifacts["paths"] == ["codekavach-report/", "result.json"]


def scan_script(source: str) -> str:
    if source == "github":
        step = next(s for s in github_steps() if s.get("name") == "Scan")
        script: str = step["run"]
        return script
    lines: list[str] = gitlab_job()["script"]
    return next(line for line in lines if "codekavach scan" in line)


def run_script(script: str, code: int, cwd: Path) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    stub = f"codekavach() {{ echo '{{}}'; return {code}; }}\n"
    return subprocess.run(
        [BASH, "-eo", "pipefail", "-c", stub + script],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


@needs_bash
@pytest.mark.parametrize("source", ["github", "gitlab"])
@pytest.mark.parametrize(
    ("code", "message"),
    [
        (0, "clean"),
        (1, "findings at or above the threshold"),
        (2, "codekavach exited with 2"),
        (3, "privacy control refused the run"),
        (4, "internal failure in CodeKavach"),
        (130, "codekavach exited with 130"),
    ],
)
def test_the_ci_script_fails_on_every_non_zero_code_and_names_each_one(
    tmp_path: Path, source: str, code: int, message: str
) -> None:
    done = run_script(scan_script(source), code, tmp_path)
    assert done.returncode == code, done.stderr
    assert message in done.stdout, done.stdout
    assert (tmp_path / "result.json").read_text(encoding="utf-8").strip() == "{}"


@needs_bash
def test_code_4_is_reported_differently_from_codes_1_and_3(tmp_path: Path) -> None:
    for source in ("github", "gitlab"):
        messages = {
            code: run_script(scan_script(source), code, tmp_path).stdout for code in (1, 3, 4)
        }
        assert len(set(messages.values())) == 3, source
        assert "report it" in messages[4]


def real_provider_file() -> str:
    step = next(
        s for s in yaml_documents() if isinstance(s, list) and "Scan with a provider" in str(s)
    )
    script: str = step[0]["run"]
    match = re.search(r"<<'EOF'\n(.*?)\nEOF\n", script, re.DOTALL)
    assert match is not None
    return match.group(1)


def test_the_provider_file_of_the_ci_example_names_the_key_by_reference() -> None:
    settings = Settings.model_validate(tomllib.loads(real_provider_file()))
    provider = settings.llm.providers["primary"]
    assert provider.api_key == "env:ANTHROPIC_API_KEY"  # pragma: allowlist secret
    step = next(s for s in yaml_documents() if isinstance(s, list))[0]
    assert step["env"]["CODEKAVACH_ACCEPT_EGRESS"] == "1"
    assert "secrets.ANTHROPIC_API_KEY" in step["env"]["ANTHROPIC_API_KEY"]
    assert "--config" in step["run"]


def test_every_toml_block_of_the_guide_loads_as_settings_without_a_plaintext_key() -> None:
    toml_blocks = [b for b in blocks(TEXT) if b.info == "toml"]
    assert toml_blocks
    for block in toml_blocks:
        settings = Settings.model_validate(tomllib.loads("\n".join(block.lines)))
        for provider in settings.llm.providers.values():
            assert provider.api_key is None or provider.api_key.startswith("env:")


def test_no_url_other_than_the_project_repository_is_cited() -> None:
    for url in re.findall(r"https?://[^\s)\]>\"']+", TEXT):
        assert url.startswith(PROJECT_URL), url


def test_no_claim_word_is_left_unexplained() -> None:
    for number, line in enumerate(TEXT.splitlines(), start=1):
        for hit in CLAIM_WORDS.finditer(line):
            allowed = any(phrase in line for phrase in ALLOWED_PHRASES)
            assert allowed, f"guide line {number}: {hit.group(0)!r}; reword it or explain it"


def test_the_guide_is_linked_from_the_readme_and_the_reference() -> None:
    assert "docs/guide/cli.md" in (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    reference = (REPO_ROOT / "docs" / "reference" / "cli.md").read_text(encoding="utf-8")
    assert "../guide/cli.md" in reference.split("## Contents", 1)[0]
