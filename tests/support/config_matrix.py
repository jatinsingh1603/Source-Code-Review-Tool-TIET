"""Building every combination of the six configuration sources for the precedence matrix (E03-43).

The six sources, lowest to highest: user file, project file, profile, ``CODEKAVACH_*`` environment,
CLI flags, and the organisation policy lock above all. ``build_layers`` turns a bit mask (bit 0 is
the user file, bit 5 the lock) into files in a ``ConfigSandbox`` and the keyword arguments for
``load_settings``. Static inputs live in ``tests/fixtures/config/precedence/<kind>/``; the
environment and CLI values are held here so each source has a distinct, recognisable value.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tests.support.config import ConfigSandbox

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "config" / "precedence"
SOURCES = ("user", "project", "profile", "env", "cli", "lock")
LABELS = {"user": "U", "project": "P", "profile": "pr", "env": "E", "cli": "C", "lock": "L"}
PROFILE = "matrix"
MASKS = range(2 ** len(SOURCES))


@dataclass(frozen=True)
class Kind:
    """One setting under test: its key, its fixture directory and the value each source gives."""

    name: str
    key: str
    env_name: str
    env_value: str
    cli: dict[str, Any]
    values: dict[str, Any]
    default: Any


SCALAR = Kind(
    name="scalar",
    key="scan.max_file_size_kb",
    env_name="CODEKAVACH_SCAN__MAX_FILE_SIZE_KB",
    env_value="104",
    cli={"scan": {"max_file_size_kb": 105}},
    values={"user": 101, "project": 102, "profile": 103, "env": 104, "cli": 105, "lock": 106},
    default=1024,
)
LIST = Kind(
    name="list",
    key="reporting.formats",
    env_name="CODEKAVACH_REPORTING__FORMATS",
    env_value="docx",
    cli={"reporting": {"formats": ["pdf"]}},
    values={
        "user": ["csv"],
        "project": ["xlsx"],
        "profile": ["markdown"],
        "env": ["docx"],
        "cli": ["pdf"],
        "lock": ["json"],
    },
    default=["html", "sarif", "json"],
)
UNION = Kind(
    name="union",
    key="privacy.never_send",
    env_name="CODEKAVACH_PRIVACY__NEVER_SEND",
    env_value="e/**",
    cli={"privacy": {"never_send": ["c/**"]}},
    values={
        "user": ["u/**"],
        "project": ["p/**"],
        "profile": ["pr/**"],
        "env": ["e/**"],
        "cli": ["c/**"],
        "lock": ["l/**"],
    },
    default=[],
)


def present(mask: int) -> tuple[str, ...]:
    """The sources in ``mask``, lowest precedence first."""
    return tuple(name for bit, name in enumerate(SOURCES) if mask >> bit & 1)


def label(mask: int) -> str:
    """A test id such as ``U-P-pr-E-C-L`` for the sources present, or ``none``."""
    return "-".join(LABELS[name] for name in present(mask)) or "none"


def fixture_text(kind: Kind, name: str) -> str:
    return (FIXTURES / kind.name / f"{name}.toml").read_text(encoding="utf-8")


def build_layers(
    mask: int, sandbox: ConfigSandbox, kind: Kind = SCALAR, *, enforcement: str = "reject"
) -> dict[str, Any]:
    """Write the files and environment for ``mask``; return the ``load_settings`` keywords.

    The profile ``matrix`` is defined in the user file, so a mask with the profile but not the user
    writes a user file holding only the profile definition.
    """
    names = present(mask)
    user_text = fixture_text(kind, "user") if "user" in names else ""
    if "profile" in names:
        user_text = (
            f"{user_text}\n{fixture_text(kind, 'profile')}"
            if user_text
            else fixture_text(kind, "profile")
        )
    if user_text:
        sandbox.write_user(user_text)
    if "project" in names:
        sandbox.write_project(fixture_text(kind, "project"))
    if "lock" in names:
        sandbox.write_policy(
            fixture_text(kind, "policy_clamp" if enforcement == "clamp" else "policy")
        )
    if "env" in names:
        sandbox.env[kind.env_name] = kind.env_value
    keywords: dict[str, Any] = {}
    if "profile" in names:
        keywords["profile"] = PROFILE
    if "cli" in names:
        keywords["cli_overrides"] = kind.cli
    return keywords


def expected_winner(mask: int) -> str:
    """The highest present source below the lock, or ``default``."""
    names = [name for name in present(mask) if name != "lock"]
    return names[-1] if names else "default"
