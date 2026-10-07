"""``docs/reference/cli-doctor.md`` lists every check, as it is registered (E05-21)."""

import re
from pathlib import Path

from codekavach.cli import doctor, doctor_checks
from codekavach.cli.doctor import Check
from codekavach.config import Settings

PAGE = Path(__file__).resolve().parents[3] / "docs" / "reference" / "cli-doctor.md"
ROW = re.compile(r"^\| `([^`]+)` \| ([^|]+) \| (yes|no) \| (yes|no)[^|]* \|", re.MULTILINE)


def documented() -> dict[str, tuple[set[str], bool, bool]]:
    """name -> (categories, required, network) from the table of the page."""
    text = PAGE.read_text(encoding="utf-8")
    found = {}
    for name, category, required, network in ROW.findall(text):
        found[name] = (
            {part.strip() for part in category.split(",")},
            required == "yes",
            network == "yes",
        )
    return found


def template(name: str) -> str:
    """``provider:lab:reachable`` -> ``provider:<id>:reachable``; other names are unchanged."""
    if name.startswith("provider:"):
        return re.sub(r"^provider:[^:]+:", "provider:<id>:", name)
    if name.startswith("engine:"):
        return "engine:<name>"
    if name.endswith(":settings"):
        return "<category>:settings"
    return name


def sample_checks() -> list[Check]:
    sample = Settings.model_validate(
        {
            "llm": {"providers": {"lab": {"kind": "anthropic", "model": "m"}}},
            "engines": {"enabled": ["semgrep"]},
            "reporting": {"formats": ["pdf"]},
        }
    )
    checks = [*doctor_checks.external_checks(sample), *doctor_checks.settings_unavailable()]
    return [check for check in checks if not check.name.startswith("provider:mock:")]


def test_every_static_check_is_on_the_page_with_its_flags() -> None:
    rows = documented()
    for check in doctor.all_checks():
        assert check.name in rows, check.name
        categories, required, network = rows[check.name]
        assert categories == {check.category}, check.name
        assert required is check.required, check.name
        assert network is check.needs_network, check.name


def test_every_settings_driven_check_is_on_the_page_with_its_flags() -> None:
    rows = documented()
    seen = set()
    for check in sample_checks():
        key = template(check.name)
        assert key in rows, key
        categories, required, network = rows[key]
        assert check.category in categories, key
        assert required is check.required, key
        assert network is check.needs_network, key
        seen.add(key)
    assert seen == {
        "engine:<name>",
        "provider:<id>:configured",
        "provider:<id>:reachable",
        "report:pdf",
        "report:fonts",
        "<category>:settings",
    }


def test_the_page_lists_nothing_that_does_not_exist() -> None:
    known = {check.name for check in doctor.all_checks()} | {
        template(check.name) for check in sample_checks()
    }
    assert set(documented()) == known


def test_the_page_names_every_reason_code_and_the_gates() -> None:
    text = PAGE.read_text(encoding="utf-8")
    for code in ("unreachable", "unauthorised", "model_not_found", "rate_limited", "tls_error"):
        assert f"`{code}`" in text
    for code in ("timeout", "bad_response"):
        assert f"`{code}`" in text
    for phrase in (
        "--probe-providers",
        "--accept-egress",
        "--offline",
        "llm.allow_remote",
        "consent required",
        "privacy level L0 sends nothing",
    ):
        assert phrase in text, phrase


def test_the_page_is_linked_from_the_command_reference_pages() -> None:
    network = PAGE.with_name("cli-network-behaviour.md").read_text(encoding="utf-8")
    assert "docs/reference/cli-doctor.md" in network
    assert "cli-doctor.md" in (PAGE.parent / "exit-codes.md").read_text(encoding="utf-8")
