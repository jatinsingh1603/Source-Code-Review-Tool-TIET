import importlib.util
import json
import sys
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

from tests.support.workflows import load_workflow

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools/dev/check_docs.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_docs", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_docs"] = module
    spec.loader.exec_module(module)
    return module


docs = _load()

NONE: frozenset[str] = frozenset()
# Assembled at run time: neither the phrases nor an emoji are written literally in this file.
CO_AUTHOR_LINE = "-".join(["Co", "authored", "by"]) + ": Some Tool <tool@example.invalid>"
TOOL_CREDIT_LINE = " ".join(["Generated", "with"]) + " [Some Tool](https://example.invalid)"
ROCKET = chr(0x1F680)
CHECK_MARK = chr(0x2705)


def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def codes(root: Path, name: str, pending: frozenset[str] = NONE) -> list[tuple[int, str]]:
    return [(p.line, p.code) for p in docs.check_file(root / name, root, pending)]


# DOC001


def test_missing_targets_are_reported_with_file_and_line(tmp_path: Path) -> None:
    write(tmp_path, "docs/ARCHITECTURE.md", "# Architecture\n")
    write(
        tmp_path,
        "README.md",
        "# Title\n\nSee [the plan](docs/DOES_NOT_EXIST.md).\n[ok](docs/ARCHITECTURE.md)\n"
        'A [titled link](docs/missing.md "A title") and ![an image](img/missing.png).\n',
    )
    problems = docs.check_file(tmp_path / "README.md", tmp_path, NONE)
    assert [(p.path, p.line, p.code) for p in problems] == [
        ("README.md", 3, "DOC001"),
        ("README.md", 5, "DOC001"),
        ("README.md", 5, "DOC001"),
    ]
    assert "docs/DOES_NOT_EXIST.md" in problems[0].message
    assert str(problems[0]) == (
        "README.md:3: DOC001 link target does not exist: docs/DOES_NOT_EXIST.md"
    )


def test_links_resolve_against_the_directory_of_the_linking_file(tmp_path: Path) -> None:
    write(
        tmp_path, "docs/process/guide.md", "[up](../PLAN.md) [sibling](other.md) [bad](PLAN.md)\n"
    )
    write(tmp_path, "docs/process/other.md", "x\n")
    write(tmp_path, "docs/PLAN.md", "x\n")
    assert codes(tmp_path, "docs/process/guide.md") == [(1, "DOC001")]
    write(tmp_path, "docs/a.md", "[root](/docs/PLAN.md) [dir](process/) [gone](/docs/NONE.md)\n")
    assert codes(tmp_path, "docs/a.md") == [(1, "DOC001")]


def test_reference_definitions_and_angle_brackets(tmp_path: Path) -> None:
    write(tmp_path, "exists.md", "x\n")
    write(
        tmp_path,
        "a.md",
        "[one]: exists.md\n[two]: missing.md\n[three]: <https://example.invalid/a(b)c>\n"
        "A [link](<https://example.invalid/page(v=1)>) and [another](<missing two.md>).\n",
    )
    assert codes(tmp_path, "a.md") == [(2, "DOC001"), (4, "DOC001")]


# DOC002 and slugs


@pytest.mark.parametrize(
    ("heading", "slug"),
    [
        ("6.3 Invariants (enforced by tests and import contracts)",
         "63-invariants-enforced-by-tests-and-import-contracts"),
        ("`docs/process/`", "docsprocess"),
        ("The `scan` command", "the-scan-command"),
        ("What is new?", "what-is-new"),
        ("Privacy levels: L0 to L4.", "privacy-levels-l0-to-l4"),
        ("कोडकवच overview", "कोडकवच-overview"),
        ("Größe und Maße", "größe-und-maße"),
        ("snake_case and kebab-case", "snake_case-and-kebab-case"),
        ("A [link](other.md) in a heading", "a-link-in-a-heading"),
        ("Two  spaces", "two--spaces"),
    ],
)  # fmt: skip
def test_slug_generation(heading: str, slug: str) -> None:
    assert docs.slugify(heading) == slug


def test_duplicate_headings_are_numbered_and_fenced_headings_ignored() -> None:
    text = (
        "# Setup\n\n## Setup\n\n```\n# not a heading\n```\n\n"
        "### Setup ###\n\n~~~~\n## hidden\n~~~~\n"
    )
    assert docs.heading_slugs(text) == {"setup", "setup-1", "setup-2"}


def test_anchors_are_checked_in_the_target_file(tmp_path: Path) -> None:
    write(
        tmp_path,
        "docs/ARCHITECTURE.md",
        "# Architecture\n\n### 6.3 Invariants (enforced by tests and import contracts)\n",
    )
    write(
        tmp_path,
        "a.md",
        "# Top\n\n## Local part\n\n"
        "[ok](docs/ARCHITECTURE.md#63-invariants-enforced-by-tests-and-import-contracts)\n"
        "[bad](docs/ARCHITECTURE.md#no-such-heading)\n"
        "[local](#local-part) [local bad](#elsewhere)\n",
    )
    problems = docs.check_file(tmp_path / "a.md", tmp_path, NONE)
    assert [(p.line, p.code) for p in problems] == [(6, "DOC002"), (7, "DOC002")]
    assert "'#no-such-heading' in docs/ARCHITECTURE.md" in problems[0].message


# code is ignored, some targets are skipped


def test_links_in_fenced_blocks_and_inline_code_are_ignored(tmp_path: Path) -> None:
    write(
        tmp_path,
        "a.md",
        "```markdown\n[in a block](missing.md)\n```\n\n"
        "Inline `[in code](missing.md)` and ``[double `tick`](missing.md)``.\n\n"
        "~~~\n[tilde block](missing.md)\n~~~\n\n[real](missing.md)\n",
    )
    assert codes(tmp_path, "a.md") == [(11, "DOC001")]


def test_url_schemes_and_links_that_leave_the_repository_are_skipped(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(
        root,
        "README.md",
        "[web](https://example.invalid/x) [plain](http://example.invalid) "
        "[mail](mailto:someone@example.invalid)\n"
        "[issues](../../issues) [projects](../../projects) [outside](../sibling/file.md)\n",
    )
    assert codes(root, "README.md") == []


@pytest.mark.parametrize(
    "target",
    ["/Users/someone/notes.md", "/home/someone/x.md", "C:\\\\work\\\\x.md", "c:/work/x.md",
     "file:///tmp/x.md"],
)  # fmt: skip
def test_local_absolute_paths_are_doc006(tmp_path: Path, target: str) -> None:
    write(tmp_path, "a.md", f"[local]({target})\n")
    assert codes(tmp_path, "a.md") == [(1, "DOC006")]


# pending


def test_pending_links_are_informational_until_the_file_exists(tmp_path: Path) -> None:
    pending = frozenset({"docs/THREAT_MODEL.md"})
    write(
        tmp_path, "pyproject.toml", '[tool.codekavach.docs]\npending = ["docs/THREAT_MODEL.md"]\n'
    )
    write(tmp_path, "a.md", "[threats](docs/THREAT_MODEL.md) [gone](docs/OTHER.md)\n")
    problems = docs.check_file(tmp_path / "a.md", tmp_path, pending)
    assert [(p.code, p.is_failure) for p in problems] == [("DOC000", False), ("DOC001", True)]
    assert docs.stale_pending(tmp_path, pending) == []
    write(tmp_path, "a.md", "[threats](docs/THREAT_MODEL.md)\n")
    assert docs.main([str(tmp_path / "a.md")], repo_root=tmp_path) == 0
    write(tmp_path, "docs/THREAT_MODEL.md", "")
    stale = docs.stale_pending(tmp_path, pending)
    assert [(p.path, p.code) for p in stale] == [("pyproject.toml", "DOC003")]
    assert docs.check_file(tmp_path / "a.md", tmp_path, pending) == []
    assert docs.main([str(tmp_path / "a.md")], repo_root=tmp_path) == 1


# DOC004 and DOC005


@pytest.mark.parametrize("line", [CO_AUTHOR_LINE, CO_AUTHOR_LINE.upper(), TOOL_CREDIT_LINE])
def test_attribution_phrases_are_doc004(tmp_path: Path, line: str) -> None:
    write(tmp_path, "a.md", f"# Notes\n\nText.\n\n{line}\n")
    assert (5, "DOC004") in codes(tmp_path, "a.md")


@pytest.mark.parametrize("emoji", [ROCKET, CHECK_MARK, chr(0x26A0) + chr(0xFE0F)])
def test_emoji_are_doc005(tmp_path: Path, emoji: str) -> None:
    write(tmp_path, "a.md", f"# Notes\n\nShipped {emoji}\n")
    problems = docs.check_file(tmp_path / "a.md", tmp_path, NONE)
    assert [(p.line, p.code) for p in problems] == [(3, "DOC005")]
    assert problems[0].message.startswith("emoji code point U+")


def test_devanagari_and_typographic_characters_pass(tmp_path: Path) -> None:
    write(
        tmp_path,
        "a.md",
        "# कोडकवच (CodeKavach)\n\nकवच means armour. Arrows → and ≥, café, 日本語.\n",
    )
    assert codes(tmp_path, "a.md") == []


def test_the_patterns_are_those_of_the_commit_message_checker() -> None:
    patterns = docs._commit_patterns()
    assert patterns.__name__ == "check_commit_msg"
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "-".join(["co", "authored", "by"]) not in source
    assert ROCKET not in source


# command line


def test_exit_codes_sorted_output_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "pyproject.toml", '[tool.codekavach.docs]\nexclude = ["fixtures/**"]\n')
    write(tmp_path, "b.md", "[x](missing.md)\n")
    write(tmp_path, "a.md", f"ok\n\n[y](gone.md) {ROCKET}\n")
    write(tmp_path, "fixtures/app/README.md", "[z](nowhere.md)\n")
    write(tmp_path, "notes.txt", "[t](nowhere.md)\n")
    assert docs.main([], repo_root=tmp_path) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines == [
        "a.md:3: DOC001 link target does not exist: gone.md",
        "a.md:3: DOC005 emoji code point U+1F680",
        "b.md:1: DOC001 link target does not exist: missing.md",
    ]
    assert docs.main(["--format", "json", str(tmp_path / "b.md")], repo_root=tmp_path) == 1
    assert json.loads(capsys.readouterr().out) == [
        {
            "path": "b.md",
            "line": 1,
            "code": "DOC001",
            "message": "link target does not exist: missing.md",
        }
    ]
    write(tmp_path, "missing.md", "x\n")
    assert docs.main([str(tmp_path / "b.md")], repo_root=tmp_path) == 0
    assert capsys.readouterr().out == ""
    assert docs.main(["--format", "json", str(tmp_path / "b.md")], repo_root=tmp_path) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_claims_lists_lines_outside_code_and_exits_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(
        tmp_path,
        "a.md",
        "# Privacy\n\nWe guarantee nothing.\n\n```\nthis is the best guarantee\n```\n\n"
        "Inline `never` is code. It is 100% offline and the BEST of all.\n"
        "A guaranteed result and a bestseller do not count; `impossible` neither.\n"
        "[broken](missing.md)\n",
    )
    assert docs.main(["--claims", str(tmp_path / "a.md")], repo_root=tmp_path) == 0
    assert capsys.readouterr().out.splitlines() == [
        "a.md:3: CLAIM We guarantee nothing.",
        "a.md:9: CLAIM Inline `never` is code. It is 100% offline and the BEST of all.",
    ]
    assert docs.CLAIM_WORDS == ("never", "guarantee", "ensures", "impossible", "100%", "best")


# the repository


def test_repository_documents_pass() -> None:
    pending, exclude = docs.load_config(REPO_ROOT)
    assert "fixtures/**" in exclude
    assert docs.stale_pending(REPO_ROOT, pending) == []
    files = [
        path
        for path in docs.tracked_markdown(REPO_ROOT)
        if not any(
            docs.fnmatch.fnmatch(path.relative_to(REPO_ROOT).as_posix(), pattern)
            for pattern in exclude
        )
    ]
    assert len(files) > 40
    failures = [
        str(problem)
        for path in files
        for problem in docs.check_file(path, REPO_ROOT, pending)
        if problem.is_failure
    ]
    assert failures == []


def test_readme_web_relative_links_and_devanagari_are_fine() -> None:
    readme = REPO_ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert "../../issues" in text
    assert any("\u0900" <= char <= "\u097f" for char in text)
    assert docs.check_file(readme, REPO_ROOT, NONE) == []


def test_section_6_3_anchor_of_the_architecture_is_accepted(tmp_path: Path) -> None:
    slugs = docs.heading_slugs((REPO_ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8"))
    assert "63-invariants-enforced-by-tests-and-import-contracts" in slugs


def test_configuration_targets_ci_step_and_hook() -> None:
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    table = config["tool"]["codekavach"]["docs"]
    assert isinstance(table["pending"], list)
    assert "fixtures/**" in table["exclude"]
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert (
        "docs-check: ## Check Markdown links, anchors and style offline, and the ADR index\n"
        "\tuv run python tools/dev/check_docs.py\n"
        "\tuv run python tools/dev/new_adr.py --check\n"
    ) in makefile
    assert "\tuv run python tools/dev/check_docs.py --claims $(files)\n" in makefile
    lint = load_workflow(REPO_ROOT / ".github/workflows/ci.yml")["jobs"]["lint"]
    assert any(step.get("run") == "make docs-check" for step in lint["steps"])
    hooks = (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    block = hooks.split("- id: docs-check\n", 1)[1].split("- id:", 1)[0]
    assert "entry: uv run python tools/dev/check_docs.py\n" in block
    assert "files: \\.md$\n" in block
    assert "`check_docs.py`" in (REPO_ROOT / "tools/dev/README.md").read_text(encoding="utf-8")
