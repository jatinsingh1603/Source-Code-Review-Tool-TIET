"""The organisation policy administrator guide covers the whole policy format (E03-42).

The page is read by a security team and quoted to an auditor, so these tests keep it complete
(every rule of ``OrgPolicy``, every error code from 050 to 056) and keep its limits stated, in the
section that qualifies the controls. The examples in the page are validated by
``test_docs_examples.py`` through the ``<!-- org-policy -->`` marker.
"""

import re
import tomllib
from pathlib import Path

import pytest

from codekavach.config.errors import ConfigErrorCode
from codekavach.config.introspect import FieldRef, iter_fields
from codekavach.config.orgpolicy.model import OrgPolicy

ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "docs"
PAGE = DOCS / "configuration" / "organisation-policy.md"
EXAMPLES = (
    DOCS / "examples" / "policy.minimal.toml",
    DOCS / "examples" / "policy.bank-strict.toml",
)
POLICY_CODES = [code for code in ConfigErrorCode if code.value.startswith("CK-CFG-05")]
LIMIT_PHRASES = ("local administrator", "process environment", "freshness", "Windows")


def section(title: str) -> str:
    """The text of the ``## title`` section of the page, up to the next ``##`` heading."""
    text = PAGE.read_text(encoding="utf-8")
    match = re.search(rf"^## {re.escape(title)}\n(?P<body>.*?)(?=^## |\Z)", text, re.S | re.M)
    assert match is not None, f"no section '{title}'"
    return match["body"]


def test_the_page_has_every_required_section() -> None:
    headings = re.findall(r"^## (.+)$", PAGE.read_text(encoding="utf-8"), re.M)
    assert headings == [
        "Purpose and scope",
        "File format",
        "Discovery and cumulative application",
        "Enforcement",
        "File trust checks",
        "SHA-256 pin",
        "Signing workflow",
        "Project trust switch",
        "Inspecting the active policy",
        "Limits",
        "Roll-out checklist",
    ]


@pytest.mark.parametrize("ref", list(iter_fields(OrgPolicy)), ids=lambda ref: ref.key)
def test_every_rule_field_is_in_the_file_format_section(ref: FieldRef) -> None:
    key = ref.key
    rows = [line for line in section("File format").splitlines() if line.startswith(f"| `{key}` |")]
    assert len(rows) == 1, f"{key} must have exactly one row in the file format table"
    cells = [cell.strip() for cell in rows[0].strip().strip("|").split("|")]
    assert len(cells) == 4
    assert all(cells), f"{key}: every cell of the row is filled in"
    assert cells[3].startswith("`")  # the example line is code


@pytest.mark.parametrize("code", POLICY_CODES, ids=lambda code: code.value)
def test_every_policy_error_code_is_explained(code: ConfigErrorCode) -> None:
    rows = [line for line in PAGE.read_text(encoding="utf-8").splitlines() if code.value in line]
    table_rows = [line for line in rows if line.startswith("|")]
    assert table_rows, f"{code.value} has no row in the file trust checks table"
    cells = [cell.strip() for cell in table_rows[0].strip().strip("|").split("|")]
    assert cells[1], f"{code.value}: the cause is empty"


def test_the_policy_codes_are_exactly_050_to_056() -> None:
    assert [code.value for code in POLICY_CODES] == [f"CK-CFG-05{n}" for n in range(7)]


@pytest.mark.parametrize("phrase", LIMIT_PHRASES)
def test_the_limits_section_states_the_limit(phrase: str) -> None:
    assert phrase in section("Limits")


def test_the_limits_come_before_the_checklist() -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert text.index("## Limits") < text.index("## Roll-out checklist")


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_the_example_policies_are_referenced_and_valid(path: Path) -> None:
    assert f"(../examples/{path.name})" in PAGE.read_text(encoding="utf-8")
    OrgPolicy.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))


def test_the_checklist_has_the_rollout_steps() -> None:
    items = [
        line for line in section("Roll-out checklist").splitlines() if line.startswith("- [ ]")
    ]
    assert len(items) == 10
    text = "\n".join(items)
    for needle in (
        "floor",
        "reject",
        "expiry",
        "key pair",
        "0644",
        "config policy show",
        "--strict",
    ):
        assert needle in text, needle


def test_the_guide_is_linked_from_the_user_guide() -> None:
    assert "(organisation-policy.md)" in (DOCS / "configuration" / "README.md").read_text(
        encoding="utf-8"
    )


# --- the checks are live ----------------------------------------------------------------------


def test_the_section_helper_stops_at_the_next_heading() -> None:
    body = section("SHA-256 pin")
    assert "CODEKAVACH_ORG_POLICY_SHA256" in body
    assert "## " not in body
    assert "Generate the key pair" not in body


def test_a_missing_section_is_reported() -> None:
    with pytest.raises(AssertionError, match="no section"):
        section("Not a section")
