"""The examples in docs/configuration/*.md are executed, not trusted (E03-41).

Four checks over every Markdown page in ``docs/configuration``:

- every fenced ``toml`` block parses;
- a block preceded by ``<!-- project-file -->`` (or ``<!-- user-file -->``) loads through
  ``load_settings`` as that file, in a ``ConfigSandbox``;
- a block fenced ``toml-invalid`` must be preceded by ``<!-- expect: CK-CFG-nnn -->`` and must fail
  to load as a project file with exactly that code;
- every ``codekavach`` command in a ``console`` block exists (``--help`` exits 0).

A fifth check keeps the wording of the guide (README.md) measured: a line that uses an
absolute word names the test or issue that enforces the claim. The generated reference is exempt.
"""

import re
import shlex
import tomllib
from pathlib import Path

import pytest
import typer.main

from codekavach.cli.app import app
from codekavach.config.errors import ConfigError
from tests.support.cli import run_cli
from tests.support.config import ConfigSandbox
from tests.support.doc_blocks import Block, extract_blocks
from tests.support.help_snapshots import command_paths

DOCS = Path(__file__).resolve().parents[3] / "docs" / "configuration"
EXPECT = re.compile(r"^expect:\s*(?P<code>CK-CFG-\d{3})$")
ENV_ASSIGNMENT = re.compile(r"^[A-Z_][A-Z0-9_]*=\S*$")
COMMAND_WORD = re.compile(r"^[a-z][a-z-]*$")
ABSOLUTE = re.compile(r"\b(never|guarantees?|ensures?|impossible)\b|100%", re.IGNORECASE)
ENFORCED_BY = re.compile(r"E\d{2}-\d{2}|#\d+|\btest_\w+|ADR-\d{4}|tests/")


def pages() -> list[Path]:
    return sorted(DOCS.glob("*.md"))


def all_blocks() -> list[Block]:
    return [
        block
        for page in pages()
        for block in extract_blocks(page.read_text(encoding="utf-8"), page.name)
    ]


def blocks_of(language: str, *, marker: str | None = None) -> list[Block]:
    return [
        block
        for block in all_blocks()
        if block.language == language and (marker is None or block.marker == marker)
    ]


def load_as(block: Block, sandbox: ConfigSandbox, *, as_file: str) -> None:
    """Write ``block`` as the project or user file of ``sandbox`` and load the configuration."""
    if as_file == "user":
        sandbox.write_user(block.text)
    else:
        sandbox.write_project(block.text)
    sandbox.load()


def command_path(line: str) -> list[str] | None:
    """The command words of a ``codekavach ...`` line, or None for any other line."""
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    while tokens and ENV_ASSIGNMENT.match(tokens[0]):
        tokens = tokens[1:]
    if not tokens or tokens[0] != "codekavach":
        return None
    path: list[str] = []
    for token in tokens[1:]:
        if not COMMAND_WORD.match(token):
            break
        path.append(token)
    return path


# --- the real pages -----------------------------------------------------------------------------


def test_the_pages_contain_examples() -> None:
    assert len(blocks_of("toml")) >= 6
    assert len(blocks_of("toml-invalid")) >= 2
    assert len(blocks_of("console")) >= 4


@pytest.mark.parametrize("block", blocks_of("toml"), ids=lambda block: block.id)
def test_every_toml_block_parses(block: Block) -> None:
    tomllib.loads(block.text)


@pytest.mark.parametrize(
    "block", blocks_of("toml", marker="project-file"), ids=lambda block: block.id
)
def test_project_file_blocks_load(block: Block, config_sandbox: ConfigSandbox) -> None:
    load_as(block, config_sandbox, as_file="project")


@pytest.mark.parametrize("block", blocks_of("toml", marker="user-file"), ids=lambda block: block.id)
def test_user_file_blocks_load(block: Block, config_sandbox: ConfigSandbox) -> None:
    load_as(block, config_sandbox, as_file="user")


@pytest.mark.parametrize("block", blocks_of("toml-invalid"), ids=lambda block: block.id)
def test_invalid_blocks_fail_with_their_stated_code(
    block: Block, config_sandbox: ConfigSandbox
) -> None:
    expected = EXPECT.match(block.marker or "")
    assert expected is not None, f"{block.id}: add <!-- expect: CK-CFG-nnn --> above the block"
    with pytest.raises(ConfigError) as info:
        load_as(block, config_sandbox, as_file="project")
    assert expected["code"] in {issue.code.value for issue in info.value.issues}


def command_tree() -> set[tuple[str, ...]]:
    return set(command_paths(typer.main.get_command(app)))


def console_commands() -> list[tuple[str, ...]]:
    """The command words that each documented ``codekavach`` line starts with."""
    found: set[tuple[str, ...]] = set()
    for block in blocks_of("console"):
        for line in block.text.splitlines():
            words = command_path(line.strip())
            if words is not None:
                found.add(tuple(words))
    return sorted(found)


def resolve(
    words: tuple[str, ...], tree: set[tuple[str, ...]]
) -> tuple[tuple[str, ...], str | None]:
    """The longest command path in ``words`` and the word that wrongly follows a group, if any."""
    path: tuple[str, ...] = ()
    for word in words:
        if (*path, word) not in tree:
            break
        path = (*path, word)
    is_group = any(len(other) > len(path) and other[: len(path)] == path for other in tree)
    leftover = words[len(path)] if len(words) > len(path) and is_group else None
    return path, leftover


def test_the_console_blocks_name_commands() -> None:
    paths = {resolve(words, command_tree())[0] for words in console_commands()}
    assert ("config", "validate") in paths
    assert ("config", "key", "set") in paths


@pytest.mark.parametrize("words", console_commands(), ids=lambda words: " ".join(words) or "root")
def test_every_documented_command_exists(
    words: tuple[str, ...], config_sandbox: ConfigSandbox
) -> None:
    path, leftover = resolve(words, command_tree())
    assert leftover is None, f"codekavach {' '.join(path)} has no command '{leftover}'"
    assert path, f"codekavach {' '.join(words)}: no such command"
    result = run_cli(
        [*path, "--help"],
        cwd=config_sandbox.root,
        home=config_sandbox.home,
        env=config_sandbox.env,
    )
    assert result.exit_code == 0, f"codekavach {' '.join(path)} --help: {result.stderr}"


def test_absolute_words_name_what_enforces_them() -> None:
    guide = DOCS / "README.md"
    offenders = [
        f"{guide.name}:{number}: {line.strip()}"
        for number, line in enumerate(guide.read_text(encoding="utf-8").splitlines(), start=1)
        if ABSOLUTE.search(line) and not ENFORCED_BY.search(line)
    ]
    assert offenders == []


# --- the extractor and the validators are live --------------------------------------------------

SAMPLE = """\
Intro.

<!-- project-file -->
```toml
[scan]
jobs = 2
```

<!-- expect: CK-CFG-041 -->
```toml-invalid
[privacy]
level = "L1"
```

```console
CODEKAVACH_PROFILE=ci codekavach config show --origin
$ codekavach not-a-command
codekavach scan .
```

```toml
[unmarked]
```
"""


def test_extraction_reads_language_marker_and_line() -> None:
    blocks = extract_blocks(SAMPLE, "sample.md")
    assert [(b.language, b.marker, b.line) for b in blocks] == [
        ("toml", "project-file", 4),
        ("toml-invalid", "expect: CK-CFG-041", 10),
        ("console", None, 15),
        ("toml", None, 21),
    ]
    assert blocks[0].text == "[scan]\njobs = 2\n"


def test_a_marker_must_directly_precede_its_block() -> None:
    text = "<!-- project-file -->\nSome prose in between.\n```toml\n[scan]\n```\n"
    assert extract_blocks(text)[0].marker is None


def test_command_path_strips_variables_and_stops_at_arguments() -> None:
    assert command_path("CODEKAVACH_PROFILE=ci codekavach config show --origin") == [
        "config",
        "show",
    ]
    assert command_path("codekavach scan .") == ["scan"]
    assert command_path("codekavach config key set primary --stdin") == [
        "config",
        "key",
        "set",
        "primary",
    ]
    assert command_path("$ codekavach scan") is None
    assert command_path("echo codekavach") is None
    assert command_path("codekavach 'unterminated") is None


def test_the_absolute_word_check_is_live() -> None:
    assert ABSOLUTE.search("It never leaks.")
    assert ABSOLUTE.search("This ensures privacy")
    assert not ABSOLUTE.search("privacy.never_send lists globs")
    assert ENFORCED_BY.search("Refused (E03-19).")
    assert not ENFORCED_BY.search("Refused.")


def test_a_failing_project_block_is_reported(config_sandbox: ConfigSandbox) -> None:
    block = Block("sample.md", 1, "toml", '[privacy]\nlevel = "L1"\n', "project-file")
    with pytest.raises(ConfigError):
        load_as(block, config_sandbox, as_file="project")


def test_an_invalid_block_without_an_expectation_is_refused() -> None:
    assert EXPECT.match("expect: CK-CFG-041")
    assert EXPECT.match("project-file") is None
    assert EXPECT.match("expect: CK-CFG-41") is None
