"""Schema compatibility gate (E02-24)."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from codekavach.core.models.compat import classify_change
from codekavach.core.models.export import INDEX_FILE, compat_check

BASE: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 50, "pattern": "^[a-z]+$"},
        "level": {"enum": ["L1", "L2"]},
        "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
        "note": {"type": "string"},
    },
    "required": ["name"],
    "$defs": {"Part": {"type": "object", "properties": {"x": {"type": "integer"}}}},
}


def changed(path: list[str | int], value: Any = None, *, delete: bool = False) -> dict[str, Any]:
    """A deep copy of BASE with the value at ``path`` replaced (or deleted)."""
    copy: dict[str, Any] = json.loads(json.dumps(BASE))
    node: Any = copy
    for key in path[:-1]:
        node = node[key]
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return copy


CASES = {
    "property removed": (changed(["properties", "note"], delete=True), "breaking"),
    "optional property added": (changed(["properties", "extra"], {"type": "string"}), "additive"),
    "required property added": (
        {**changed(["properties", "extra"], {"type": "string"}), "required": ["name", "extra"]},
        "breaking",
    ),
    "required property added with default": (
        {
            **changed(["properties", "extra"], {"type": "string", "default": "x"}),
            "required": ["name", "extra"],
        },
        "additive",
    ),
    "property becomes required": (changed(["required"], ["name", "note"]), "breaking"),
    "property becomes optional": (changed(["required"], []), "additive"),
    "type changed": (changed(["properties", "note", "type"], "integer"), "breaking"),
    "enum member removed": (changed(["properties", "level", "enum"], ["L1"]), "breaking"),
    "enum member added": (changed(["properties", "level", "enum"], ["L1", "L2", "L3"]), "additive"),
    "minLength raised": (changed(["properties", "name", "minLength"], 2), "breaking"),
    "maxLength lowered": (changed(["properties", "name", "maxLength"], 10), "breaking"),
    "maxLength raised": (changed(["properties", "name", "maxLength"], 99), "additive"),
    "minLength lowered": (changed(["properties", "name", "minLength"], 0), "additive"),
    "pattern changed": (changed(["properties", "name", "pattern"], "^[a-z0-9]+$"), "breaking"),
    "description only": (changed(["properties", "note", "description"], "A note."), "none"),
    "title, examples and default": (
        changed(
            ["properties", "note"],
            {"type": "string", "title": "N", "examples": ["a"], "default": "b"},
        ),
        "none",
    ),
    "nested items type changed": (
        changed(["properties", "tags", "items", "type"], "integer"),
        "breaking",
    ),
    "nested items maxItems lowered": (changed(["properties", "tags", "maxItems"], 3), "breaking"),
    "defs property removed": (changed(["$defs", "Part", "properties"], {}), "breaking"),
    "defs renamed with the same structure": (
        {**changed(["$defs"], {"Piece": BASE["$defs"]["Part"]})},
        "none",
    ),
    "defs renamed and changed": (
        changed(["$defs"], {"Piece": {"type": "object", "properties": {}}}),
        "breaking",
    ),
    "unrecognised keyword": (
        changed(["properties", "note", "contentEncoding"], "base64"),
        "breaking",
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_rule_table(name: str) -> None:
    new, level = CASES[name]
    report = classify_change(BASE, new)
    assert report.level == level, report.reasons


def test_type_list_member_removed_and_added() -> None:
    old = changed(["properties", "note", "type"], ["string", "null"])
    assert classify_change(old, BASE).level == "breaking"
    assert classify_change(BASE, old).level == "additive"


def test_anyof_by_position() -> None:
    old = changed(["properties", "note"], {"anyOf": [{"type": "string"}, {"type": "null"}]})
    fewer = changed(["properties", "note"], {"anyOf": [{"type": "string"}]})
    more = changed(
        ["properties", "note"],
        {"anyOf": [{"type": "string"}, {"type": "null"}, {"type": "integer"}]},
    )
    assert classify_change(old, fewer).level == "breaking"
    assert classify_change(old, more).level == "additive"


def test_reasons_name_json_pointers() -> None:
    report = classify_change(BASE, changed(["properties", "note"], delete=True))
    assert report.reasons == ("property removed at /properties/note",)
    weird = classify_change(BASE, changed(["properties", "a/b~c"], {"type": "string"}))
    assert weird.reasons == ("property added at /properties/a~1b~0c",)
    unknown = classify_change(BASE, changed(["properties", "note", "contentEncoding"], "base64"))
    assert unknown.reasons == ("unrecognised change at /properties/note/contentEncoding",)


def test_identical_schemas() -> None:
    assert classify_change(BASE, json.loads(json.dumps(BASE))).level == "none"


# --- the gate against a git repository -----------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        [  # noqa: S607 - the test runs git from PATH on purpose
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def write_schemas(repo: Path, schema: dict[str, Any], version: int) -> None:
    out = repo / "docs" / "schemas"
    out.mkdir(parents=True, exist_ok=True)
    (out / "widget.schema.json").write_text(json.dumps(schema), encoding="utf-8")
    index = {
        "models": [{"name": "Widget", "file": "widget.schema.json", "schema_version": version}]
    }
    (out / INDEX_FILE).write_text(json.dumps(index), encoding="utf-8")


def commit(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def working_tree(repo: Path) -> dict[str, str]:
    out = repo / "docs" / "schemas"
    return {path.name: path.read_text(encoding="utf-8") for path in out.iterdir()}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q")
    write_schemas(path, BASE, 1)
    commit(path, "core: base schemas")
    return path


def check(repo: Path, base: str) -> tuple[int, list[str]]:
    return compat_check(base, Path("docs/schemas"), build=lambda: working_tree(repo), cwd=repo)


@needs_git
def test_breaking_change_without_bump_fails(repo: Path) -> None:
    write_schemas(repo, changed(["properties", "note"], delete=True), 1)
    commit(repo, "core: drop note")
    code, lines = check(repo, "HEAD~1")
    assert code == 1
    assert "widget.schema.json: breaking" in lines
    assert "  - property removed at /properties/note" in lines


@needs_git
def test_breaking_change_with_bump_passes(repo: Path) -> None:
    write_schemas(repo, changed(["properties", "note"], delete=True), 2)
    commit(repo, "core: drop note, version 2")
    code, lines = check(repo, "HEAD~1")
    assert code == 0
    assert "widget.schema.json: breaking (schema version raised)" in lines


@needs_git
def test_range_spans_every_commit(repo: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    write_schemas(repo, changed(["properties", "note"], delete=True), 1)
    commit(repo, "core: drop note")
    write_schemas(repo, changed(["properties", "note"], delete=True) | {"title": "W"}, 1)
    commit(repo, "core: a title")
    schema = changed(["properties", "note"], delete=True) | {"title": "W", "description": "D."}
    write_schemas(repo, schema, 1)
    commit(repo, "docs: describe the widget")
    assert check(repo, base)[0] == 1
    assert check(repo, "HEAD~1")[0] == 0  # the last commit alone only edits a description


@needs_git
def test_new_and_removed_files(repo: Path) -> None:
    out = repo / "docs" / "schemas"
    (out / "gadget.schema.json").write_text("{}", encoding="utf-8")
    code, lines = check(repo, "HEAD")
    assert code == 0
    assert "gadget.schema.json: additive (new file)" in lines
    (out / "widget.schema.json").unlink()
    (out / INDEX_FILE).write_text(json.dumps({"models": []}), encoding="utf-8")
    commit(repo, "core: remove the widget")
    assert check(repo, "HEAD~1")[0] == 1
    git(repo, "commit", "-q", "--allow-empty", "-m", "core: confirm [schema-remove]")
    assert check(repo, "HEAD~2")[0] == 0


@needs_git
def test_missing_base_revision_is_skipped(repo: Path) -> None:
    code, lines = check(repo, "does-not-exist")
    assert code == 0
    assert lines[0].startswith("notice: base revision")


@pytest.mark.parametrize("ref", ["-x", "--output=/tmp/x", "a b", "x" * 101, "a;b"])
def test_invalid_reference(ref: str) -> None:
    assert compat_check(ref, Path("docs/schemas")) == (2, ["invalid --compat-base reference"])


def test_missing_git_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_: object, **__: object) -> None:
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", missing)
    code, lines = compat_check("HEAD", Path("docs/schemas"))
    assert code == 0
    assert lines == ["notice: git is not available; compatibility check skipped"]


def test_git_timeout_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr(subprocess, "run", slow)
    assert compat_check("HEAD", Path("docs/schemas"))[0] == 2


def test_failing_git_show_means_a_new_file(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    index = json.dumps({"models": [{"file": "a.schema.json", "schema_version": 1}]})

    def fake(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[1] == "show" and args[2].endswith(INDEX_FILE):
            return subprocess.CompletedProcess(args, 0, index, "")
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 128, "", "fatal: path does not exist")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake)
    built = {INDEX_FILE: index, "a.schema.json": "{}"}
    code, lines = compat_check("HEAD", Path("docs/schemas"), build=lambda: built)
    assert code == 0
    assert lines == ["a.schema.json: additive (new file)"]
    assert all(call[0] == "git" for call in calls)
