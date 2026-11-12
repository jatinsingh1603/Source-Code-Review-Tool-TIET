"""Hygiene of the KavachBank fixture: what it contains, what it must not contain (E13-01).

The fixture is deliberately vulnerable code that is safe to publish for ever: every credential is a
synthetic value of ``tests/support/synthetic.py`` and is listed in the manifest, it is not
installable, nothing in the package imports it and the wheel does not contain it.
"""

import ast
import json
import tomllib
from pathlib import Path

import pytest

from codekavach.core.models import Language, RawCode
from codekavach.parsing import parse
from codekavach.privacy.detect.secrets.builtin import secret_detectors
from codekavach.privacy.detect.terms import fold
from tests.support import synthetic
from tests.support.kavachbank import (
    FIXTURE_ROOT,
    load_manifest,
    load_negative_controls,
    resolve_value_ref,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
API = FIXTURE_ROOT / "services" / "api"
WEB = FIXTURE_ROOT / "services" / "web"
SOURCES = sorted([*API.glob("*.py"), *WEB.glob("*.js")])
LANGUAGES = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT}


def relative(path: Path) -> str:
    return path.relative_to(FIXTURE_ROOT).as_posix()


def test_the_python_service_has_the_required_modules() -> None:
    names = {path.stem for path in API.glob("*.py")}
    assert len(names) >= 8
    assert {"handlers", "accounts", "interest_engine", "loan_scoring", "fraud_rules", "config",
            "db", "serialisation"} <= names  # fmt: skip


def test_the_node_service_has_the_required_modules() -> None:
    names = {path.stem for path in WEB.glob("*.js")}
    assert len(names) >= 6
    assert {"routes", "session", "renderer", "payments", "exporter", "config"} <= names


def test_the_business_logic_is_recognisable() -> None:
    text = "\n".join(path.read_text(encoding="utf-8") for path in API.glob("*.py"))
    for needle in (
        "def accrue_festival_bonus",
        "FESTIVAL_RATE",
        "SAVINGS_TIERS",
        "def monthly_maintenance_fee",
        "def maintenance_waived",
        "def eligibility_score",
        "RISK_BAND_POINTS",
        "SINGLE_TRANSFER_LIMIT",
        "VELOCITY_LIMIT",
    ):
        assert needle in text, needle


@pytest.mark.parametrize("path", SOURCES, ids=relative)
def test_every_source_file_is_valid_syntax(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        ast.parse(text)
    assert parse(relative(path), LANGUAGES[path.suffix], text).error_count == 0


def test_every_manifest_domain_term_occurs_in_the_code() -> None:
    code = fold("\n".join(path.read_text(encoding="utf-8") for path in SOURCES))
    missing = [t for t in load_manifest().business_domain_dictionary if fold(t) not in code]
    assert missing == []


def test_a_secret_scan_finds_only_values_the_manifest_lists() -> None:
    manifest = load_manifest()
    listed = {
        resolve_value_ref(secret.value_ref): (secret.file, secret.line)
        for secret in manifest.planted_secrets
    }
    allowed_lines = {
        (secret.file, secret.line + offset)
        for secret in manifest.planted_secrets
        for offset in range(len(resolve_value_ref(secret.value_ref).split("\n")))
    }
    synthetic_values = {entry.value for entry in synthetic.SYNTHETIC_SECRETS}
    found: list[tuple[str, int, str]] = []
    for path in (*SOURCES, FIXTURE_ROOT / "fixtures" / "seed" / "customers.json"):
        name, text = relative(path), path.read_text(encoding="utf-8")
        raw = text.encode("utf-8")
        for detector in secret_detectors():
            for span in detector.detect(RawCode(text), path=name, language=Language.UNKNOWN):
                value = raw[span.start_byte : span.end_byte].decode("utf-8")
                line = raw[: span.start_byte].count(b"\n") + 1
                found.append((name, line, value))
    assert found, "the secret scan should find the planted values"
    for name, line, value in found:
        assert (name, line) in allowed_lines, (name, line)
        assert any(value in secret or secret in value for secret in listed), (name, line)
        assert any(value in known or known in value for known in synthetic_values), (name, line)


def test_the_credentials_are_synthetic_and_listed() -> None:
    manifest = load_manifest()
    for secret in manifest.planted_secrets:
        value = resolve_value_ref(secret.value_ref)
        assert any(
            value in entry.value or entry.value in value for entry in synthetic.SYNTHETIC_SECRETS
        ) or (value in {v for v in vars(synthetic).values() if isinstance(v, str)})
    seed = json.loads((FIXTURE_ROOT / "fixtures" / "seed" / "customers.json").read_text("utf-8"))
    emails = [c["email"] for c in seed["customers"] if "email" in c]
    assert emails and all(email.endswith("@example.test") for email in emails)
    assert all(c["phone"].startswith(("+44 7700 900", "+91")) for c in seed["customers"])


def test_every_planted_pii_value_is_in_the_seed_file() -> None:
    seed = (FIXTURE_ROOT / "fixtures" / "seed" / "customers.json").read_text("utf-8")
    for item in load_manifest().planted_pii:
        assert resolve_value_ref(item.value_ref) in seed


def test_the_fixture_is_not_installable() -> None:
    names = {path.name for path in FIXTURE_ROOT.rglob("*") if path.is_file()}
    assert not names & {
        # requirements.txt and package.json are inventory-only fixtures for the SCA scan: no
        # lock file, no installable project, never installed.
        "pyproject.toml", "setup.py", "setup.cfg",
        "package-lock.json", "yarn.lock", "Pipfile", "poetry.lock", "__init__.py",
    }  # fmt: skip
    directories = {path.name for path in FIXTURE_ROOT.rglob("*") if path.is_dir()}
    assert not directories & {"node_modules", ".venv", "venv", "__pycache__", "site-packages"}


def test_no_package_module_imports_the_fixture() -> None:
    offenders: list[str] = []
    for path in (REPO_ROOT / "src" / "codekavach").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            if any(name.split(".")[0] in {"fixtures", "kavachbank"} for name in names):
                offenders.append(path.name)
    assert offenders == []


def test_the_wheel_and_the_gates_leave_the_fixture_out() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/codekavach"]
    assert "fixtures/**" in project["tool"]["codekavach"]["docs"]["exclude"]
    assert "^fixtures/" in project["tool"]["mypy"]["exclude"]
    assert "fixtures" in project["tool"]["ruff"]["extend-exclude"]
    # The licence and dependency gates read installed distribution metadata only, so a file of
    # the fixture can never enter them.
    licences = (REPO_ROOT / "tools" / "dev" / "check_licences.py").read_text(encoding="utf-8")
    assert "importlib.metadata" in licences and "fixtures/" not in licences


def test_the_readme_warns_and_lists_every_planted_item() -> None:
    readme = (FIXTURE_ROOT / "README.md").read_text(encoding="utf-8")
    assert "Never deploy" in readme and "deliberately vulnerable" in readme.lower()
    assert "synthetic" in readme
    manifest = load_manifest()
    ids = [
        *(v.id for v in manifest.planted_vulnerabilities),
        *(s.id for s in manifest.planted_secrets),
        *(p.id for p in manifest.planted_pii[:1]),
    ]
    for identifier in ids:
        assert identifier in readme, identifier
    assert "KB-PII-001" in readme and "KB-PII-010" in readme
    assert "KB-SAFE-001" in readme and "KB-SAFE-010" in readme
    assert len(load_negative_controls()) == 10
