"""I2 static guard (E02-28): codekavach.llm references sanitised data only."""

import textwrap
from pathlib import Path

import pytest

from codekavach.core.models.base import KavachModel
from tests.privacy._i2_guard import (
    LLM_NEUTRAL_ALLOWLIST,
    Violation,
    Zone,
    find_i2_violations,
    iter_checked_files,
    llm_allowed_names,
    model_namespace,
    raw_names,
    walk_tree,
)

pytestmark = pytest.mark.privacy
REPO_ROOT = Path(__file__).resolve().parents[2]
LLM_FILE = "src/codekavach/llm/tasks/triage.py"


def rules(source: str, *, zone: Zone = Zone.LLM, filename: str = LLM_FILE) -> list[str]:
    violations = find_i2_violations(textwrap.dedent(source), filename, zone=zone)
    return [violation.rule for violation in violations]


def test_repository_has_no_violations() -> None:
    violations = walk_tree(REPO_ROOT)
    assert not violations, "\n".join(str(violation) for violation in violations)


def test_walker_sees_the_llm_package() -> None:
    zones = [zone for _, _, zone in iter_checked_files(REPO_ROOT)]
    assert zones.count(Zone.LLM) >= 1
    assert Zone.PRIVACY in zones


# --- allow-list ----------------------------------------------------------------------------


def test_allowed_names() -> None:
    allowed = llm_allowed_names()
    assert {"SanitisedPayload", "LLMVerdict", "ContextRequest", "PlaceholderRef", "Severity"} <= (
        allowed
    )
    forbidden = {"RawCode", "CodeSlice", "Finding", "Location", "Scan", "compute_fingerprint"}
    assert not forbidden & allowed
    assert set(LLM_NEUTRAL_ALLOWLIST) <= allowed
    assert all(reason.strip() for reason in LLM_NEUTRAL_ALLOWLIST.values())


def test_raw_names() -> None:
    raw = raw_names()
    assert {"RawCode", "CodeSlice", "Evidence", "Candidate", "Finding", "Location"} <= raw
    assert not {"SanitisedPayload", "LLMVerdict", "KavachModel", "VersionedModel"} & raw


def test_unclassified_model_is_forbidden_and_raw() -> None:
    class Unclassified(KavachModel):
        value: int

    table = dict(model_namespace())
    table["Unclassified"] = Unclassified
    assert "Unclassified" not in llm_allowed_names(table)
    assert "Unclassified" in raw_names(table)


# --- the rules fire ------------------------------------------------------------------------

CLEAN = """
    from codekavach.core.models import KavachModel, Severity
    from codekavach.core.models.payload import SanitisedPayload
    from codekavach.core.models.verdict import LLMVerdict

    NOTE = "never pass a CodeSlice here"  # a RawCode comment must not fire either

    def review(payload: SanitisedPayload) -> LLMVerdict | None:
        return None
"""

SNIPPETS: dict[str, tuple[str, str, Zone]] = {
    "direct_import": ("from codekavach.core.models.slice import CodeSlice\n", "R1", Zone.LLM),
    "aliased_import": (
        "from codekavach.core.models.slice import CodeSlice as CS\n",
        "R1",
        Zone.LLM,
    ),
    "function_import": (
        "from codekavach.core.models.fingerprint import compute_fingerprint\n",
        "R1",
        Zone.LLM,
    ),
    "module_alias_attribute": (
        "import codekavach.core.models.evidence as ev\nx = ev.Evidence\n",
        "R1",
        Zone.LLM,
    ),
    "submodule_alias_attribute": (
        "from codekavach.core.models import slice as sl\ny = sl.CodeSlice\n",
        "R1",
        Zone.LLM,
    ),
    "star_import": ("from codekavach.core.models.finding import *\n", "R1", Zone.LLM),
    "type_checking_import": (
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
        "    from codekavach.core.models.location import Location\n",
        "R1",
        Zone.LLM,
    ),
    "string_annotation": ('def f(x: "CodeSlice") -> None:\n    pass\n', "R1b", Zone.LLM),
    "reexported_raw_name": ("from codekavach.privacy import Candidate\n", "R1b", Zone.LLM),
    "sanitised_text_outside_privacy": (
        "from codekavach.core.models.text import SanitisedText\nt = SanitisedText('x')\n",
        "R2",
        Zone.OTHER_SRC,
    ),
    "expose_call": ("def f(p):\n    return p.text.expose()\n", "R3", Zone.LLM),
    "open_call": ("with open('prompt.txt') as handle:\n    pass\n", "R4", Zone.LLM),
    "read_text_call": ("from pathlib import Path\nPath('p').read_text()\n", "R4", Zone.LLM),
}


def test_clean_snippet() -> None:
    assert rules(CLEAN) == []


@pytest.mark.parametrize("name", sorted(SNIPPETS))
def test_rule_fires(name: str) -> None:
    source, rule, zone = SNIPPETS[name]
    filename = LLM_FILE if zone is Zone.LLM else "src/codekavach/report/x.py"
    assert rule in rules(source, zone=zone, filename=filename)


@pytest.mark.parametrize("zone", [Zone.PRIVACY, Zone.TESTS])
def test_sanitised_text_allowed_in_privacy_and_tests(zone: Zone) -> None:
    source = "from codekavach.core.models.text import SanitisedText\nSanitisedText('x')\n"
    assert rules(source, zone=zone, filename="src/codekavach/privacy/redact/x.py") == []


def test_sanitised_text_allowed_in_text_module() -> None:
    source = "SanitisedText('x')\n"
    filename = "src/codekavach/core/models/text.py"
    assert rules(source, zone=Zone.OTHER_SRC, filename=filename) == []


def test_llm_rules_do_not_apply_elsewhere() -> None:
    source = "from codekavach.core.models.slice import CodeSlice\nopen('x')\ny.expose()\n"
    assert rules(source, zone=Zone.OTHER_SRC, filename="src/codekavach/report/x.py") == []


def test_string_literal_is_not_an_annotation() -> None:
    assert rules('x = "CodeSlice and RawCode"\nprint("Finding")\n') == []


def test_violation_text() -> None:
    violations = find_i2_violations(
        "from codekavach.core.models.slice import CodeSlice\n", LLM_FILE, zone=Zone.LLM
    )
    text = str(violations[0])
    assert text.startswith(f"{LLM_FILE}:1: I2 violation: R1")
    assert "docs/ARCHITECTURE.md section 6.3" in text


def test_unparseable_source() -> None:
    violations = find_i2_violations("def (:\n", LLM_FILE, zone=Zone.LLM)
    assert violations == [Violation(LLM_FILE, 1, "parse", "unparseable file")]


# --- the walker ----------------------------------------------------------------------------


def test_walker_on_a_temporary_tree(tmp_path: Path) -> None:
    llm = tmp_path / "src" / "codekavach" / "llm"
    (llm / "tasks" / "deep").mkdir(parents=True)
    (llm / "x.py").write_text("from codekavach.core.models import CodeSlice\n", encoding="utf-8")
    (llm / "tasks" / "deep" / "y.py").write_text("p.expose()\n", encoding="utf-8")
    (llm / "tasks" / "broken.py").write_text("def (:\n", encoding="utf-8")
    (llm / "tasks" / "latin1.py").write_bytes(b"x = '\xff'\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("SanitisedText('x')\n", encoding="utf-8")
    violations = [str(violation) for violation in walk_tree(tmp_path)]
    assert any("x.py:1: I2 violation: R1" in text for text in violations)
    assert any("deep/y.py:1: I2 violation: R3" in text for text in violations)
    assert any("broken.py:1: I2 violation: parse unparseable file" in text for text in violations)
    assert any("latin1.py:1: I2 violation: parse" in text for text in violations)
    assert not any("tests/t.py" in text for text in violations)
