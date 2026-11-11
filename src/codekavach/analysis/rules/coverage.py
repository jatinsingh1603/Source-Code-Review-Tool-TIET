"""The coverage document of the shipped rule packs (E16-03).

Owning epic: E16. ``docs/reference/rule-coverage.md`` lists, per language, which OWASP Top 10
category and which CWE Top 25 entries the packs cover and which they do not, so the report's
limitations section can say what a clean scan does not rule out. It is generated from the loaded
packs, never edited by hand::

    uv run python -m codekavach.analysis.rules.coverage          # write
    uv run python -m codekavach.analysis.rules.coverage --check  # exit 1 when the file is stale

A CWE counts as covered for a language when at least one rule of that language lists it in
``metadata.cwe``. The Top 25 list is the 2025 edition of MITRE's published ranking (REFERENCE.md);
the OWASP names are the 2021 edition.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from codekavach.analysis.rules.dsl import RuleDef
from codekavach.analysis.rules.loader import load_pack

ROOT: Final = Path(__file__).resolve().parents[4]
DEFAULT_PACK: Final = ROOT / "rules" / "mit" / "packs" / "default"
DOCUMENT: Final = ROOT / "docs" / "reference" / "rule-coverage.md"

OWASP_2021: Final = (
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
)
CWE_TOP25_2025: Final = (
    (79, "Cross-site Scripting"),
    (89, "SQL Injection"),
    (352, "Cross-Site Request Forgery"),
    (862, "Missing Authorization"),
    (787, "Out-of-bounds Write"),
    (22, "Path Traversal"),
    (416, "Use After Free"),
    (125, "Out-of-bounds Read"),
    (78, "OS Command Injection"),
    (94, "Code Injection"),
    (120, "Classic Buffer Overflow"),
    (434, "Unrestricted Upload of File with Dangerous Type"),
    (476, "NULL Pointer Dereference"),
    (121, "Stack-based Buffer Overflow"),
    (502, "Deserialization of Untrusted Data"),
    (122, "Heap-based Buffer Overflow"),
    (863, "Incorrect Authorization"),
    (20, "Improper Input Validation"),
    (284, "Improper Access Control"),
    (200, "Exposure of Sensitive Information"),
    (306, "Missing Authentication for Critical Function"),
    (918, "Server-Side Request Forgery"),
    (77, "Command Injection"),
    (639, "Authorization Bypass Through User-Controlled Key"),
    (770, "Allocation of Resources Without Limits or Throttling"),
)
ABSENT_NOTES: Final = {
    352: "needs knowledge of the framework's CSRF middleware across files",
    125: "out-of-bounds reads need bounds reasoning that pattern rules do not have",
    20: "a generic weakness: rules map to the specific class instead",
    284: "a category weakness: rules map to CWE-862, CWE-863 and CWE-639",
    200: "needs data classification; belongs to the redaction layer and the reasoning step",
    306: "needs the application's authentication design; reported as an authorisation hotspot",
    770: "needs resource-limit reasoning; not attempted by pattern rules",
    121: "stack versus heap placement is not decided by a pattern; see CWE-120 and CWE-787",
    122: "stack versus heap placement is not decided by a pattern; see CWE-120 and CWE-787",
}
MEMORY_CWES: Final = frozenset({787, 416, 125, 476, 120, 121, 122})
MEMORY_UNSAFE: Final = frozenset({"c", "cpp"})
LANGUAGE_ORDER: Final = ("python", "javascript", "c", "cpp")


def _rules_for(rules: Sequence[RuleDef], language: str) -> list[RuleDef]:
    return [rule for rule in rules if language in rule.languages]


def _languages(rules: Sequence[RuleDef]) -> list[str]:
    present = {language for rule in rules for language in rule.languages}
    return [language for language in LANGUAGE_ORDER if language in present]


def _owasp_rows(rules: Sequence[RuleDef]) -> list[str]:
    lines = ["| Category | Rules | Status |", "|---|---|---|"]
    for key, name in OWASP_2021:
        count = sum(1 for rule in rules if key in rule.metadata.owasp)
        status = "covered" if count else "not covered"
        lines.append(f"| {key} {name} | {count} | {status} |")
    return lines


def _cwe_rows(rules: Sequence[RuleDef], language: str) -> list[str]:
    lines = ["| CWE | Weakness | Rules | Status |", "|---|---|---|---|"]
    for number, name in CWE_TOP25_2025:
        count = sum(1 for rule in rules if number in rule.metadata.cwe)
        if count:
            status = "covered"
        elif number in MEMORY_CWES and language not in MEMORY_UNSAFE:
            status = "not applicable: a memory-safe language"
        else:
            status = "not covered: " + ABSENT_NOTES.get(number, "no rule yet")
        lines.append(f"| CWE-{number} | {name} | {count} | {status} |")
    return lines


def coverage_text(rules: Sequence[RuleDef], pack_id: str, version: str) -> str:
    """The Markdown text of the coverage document for ``rules``."""
    out = [
        "# Rule coverage",
        "",
        "Generated by `python -m codekavach.analysis.rules.coverage`; do not edit by hand.",
        "",
        f"Pack `{pack_id}` version {version}: {len(rules)} rules. A category or weakness is",
        "covered for a language when at least one rule of that language names it in its",
        "metadata; the count is rules, not findings, and says nothing about recall. A scan with",
        "no finding in an uncovered row means the rules did not look, not that the code is safe.",
        "OWASP names follow the 2021 edition; the weakness list is the CWE Top 25 of 2025.",
        "Memory-safety rules carry A03:2021 (Injection) as the nearest 2021 category, which has",
        "no memory-safety entry of its own.",
        "",
        "## Rules per language",
        "",
        "| Language | Rules | Hotspots |",
        "|---|---|---|",
    ]
    for language in _languages(rules):
        chosen = _rules_for(rules, language)
        hotspots = sum(1 for rule in chosen if rule.kind == "hotspot")
        out.append(f"| {language} | {len(chosen)} | {hotspots} |")
    for language in _languages(rules):
        chosen = _rules_for(rules, language)
        out += ["", f"## {language}", "", "### OWASP Top 10 (2021)", "", *_owasp_rows(chosen)]
        out += ["", "### CWE Top 25 (2025)", "", *_cwe_rows(chosen, language)]
    return "\n".join(out) + "\n"


def expected() -> str:
    """The document as the shipped default pack produces it."""
    pack = load_pack(DEFAULT_PACK)
    return coverage_text(pack.rules, pack.id, pack.version)


def check() -> list[str]:
    """A message when the document is missing or stale."""
    if not DOCUMENT.is_file():
        return [f"missing: {DOCUMENT.relative_to(ROOT).as_posix()}"]
    text = DOCUMENT.read_bytes().decode("utf-8").replace("\r\n", "\n")
    return [] if text == expected() else [f"stale: {DOCUMENT.relative_to(ROOT).as_posix()}"]


def write() -> None:
    """Write the document with LF endings."""
    DOCUMENT.parent.mkdir(parents=True, exist_ok=True)
    DOCUMENT.write_bytes(expected().encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    """Write the document, or with ``--check`` report drift and exit 1."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report a stale file, change nothing")
    arguments = parser.parse_args(argv)
    if arguments.check:
        problems = check()
        for line in problems:
            sys.stderr.write(line + chr(10))
        return 1 if problems else 0
    write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
