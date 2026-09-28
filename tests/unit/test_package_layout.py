"""The package tree matches docs/ARCHITECTURE.md section 3.

The expected sets are literal on purpose: changing the tree means changing this
test, which is the prompt to write the ADR that the architecture requires.
"""

import ast
import importlib
import pkgutil
from pathlib import Path
from types import ModuleType

import pytest

import codekavach

ADR_HINT = "update docs/ARCHITECTURE.md through an ADR before changing the tree"

EXPECTED_PACKAGES: frozenset[str] = frozenset(
    {
        "codekavach",
        "codekavach.cli",
        "codekavach.config",
        "codekavach.config.models",
        "codekavach.core",
        "codekavach.core.log",
        "codekavach.core.models",
        "codekavach.core.pipeline",
        "codekavach.core.plugins",
        "codekavach.core.store",
        "codekavach.ingest",
        "codekavach.parsing",
        "codekavach.parsing.queries",
        "codekavach.analysis",
        "codekavach.analysis.engines",
        "codekavach.analysis.rules",
        "codekavach.analysis.taint",
        "codekavach.analysis.secrets",
        "codekavach.analysis.sca",
        "codekavach.analysis.iac",
        "codekavach.analysis.aggregate",
        "codekavach.privacy",
        "codekavach.privacy.policy",
        "codekavach.privacy.detect",
        "codekavach.privacy.redact",
        "codekavach.privacy.pseudonymise",
        "codekavach.privacy.slicing",
        "codekavach.privacy.ir",
        "codekavach.privacy.vault",
        "codekavach.privacy.restore",
        "codekavach.privacy.egress",
        "codekavach.llm",
        "codekavach.llm.providers",
        "codekavach.llm.tasks",
        "codekavach.llm.prompts",
        "codekavach.llm.schema",
        "codekavach.llm.defence",
        "codekavach.risk",
        "codekavach.report",
        "codekavach.report.model",
        "codekavach.report.narrative",
        "codekavach.report.render",
        "codekavach.report.templates",
        "codekavach.integrations",
        "codekavach.integrations.github",
        "codekavach.integrations.mcp",
        "codekavach.server",
        "codekavach.eval",
    }
)

EXPECTED_MODULES: frozenset[str] = frozenset(
    {
        "codekavach.privacy.egress.guard",
        "codekavach.privacy.egress.ledger",
        "codekavach.privacy.egress.transport",
        "codekavach.llm.budget",
        "codekavach.llm.cache",
        "codekavach.llm.consensus",
        "codekavach.config.constants",
        "codekavach.config.errors",
        "codekavach.config.introspect",
        "codekavach.config.keys",
        "codekavach.config.loader",
        "codekavach.config.merge",
        "codekavach.config.toml_source",
        "codekavach.config.paths",
        "codekavach.config.profiles",
        "codekavach.config.provenance",
        "codekavach.config.overrides",
        "codekavach.config.models.base",
        "codekavach.config.models.llm",
        "codekavach.config.models.log",
        "codekavach.config.models.plugins",
        "codekavach.config.models.privacy",
        "codekavach.config.models.project",
        "codekavach.config.models.reporting",
        "codekavach.config.models.root",
        "codekavach.config.models.scan",
        "codekavach.core.log.config",
        "codekavach.core.log.redaction",
        "codekavach.core.pipeline.budget",
        "codekavach.core.pipeline.cancel",
        "codekavach.core.pipeline.context",
        "codekavach.core.pipeline.errors",
        "codekavach.core.pipeline.events",
        "codekavach.core.pipeline.graph",
        "codekavach.core.plugins.discovery",
        "codekavach.core.plugins.registry",
        "codekavach.core.store.artefacts",
        "codekavach.core.store.base",
        "codekavach.core.store.layout",
        "codekavach.core.store.memory",
        "codekavach.core.pipeline.keys",
        "codekavach.core.pipeline.orchestrator",
        "codekavach.core.pipeline.plan",
        "codekavach.core.pipeline.policy",
        "codekavach.core.pipeline.result",
        "codekavach.core.pipeline.runner",
        "codekavach.core.pipeline.salt",
        "codekavach.core.pipeline.stage",
        "codekavach.core.models.base",
        "codekavach.core.models.candidate",
        "codekavach.core.models.canonical",
        "codekavach.core.models.egress",
        "codekavach.core.models.enums",
        "codekavach.core.models.errors",
        "codekavach.core.models.evidence",
        "codekavach.core.models.export",
        "codekavach.core.models.finding",
        "codekavach.core.models.fingerprint",
        "codekavach.core.models.ids",
        "codekavach.core.models.lifecycle",
        "codekavach.core.models.location",
        "codekavach.core.models.paths",
        "codekavach.core.models.payload",
        "codekavach.core.models.scan",
        "codekavach.core.models.slice",
        "codekavach.core.models.summary",
        "codekavach.core.models.taint",
        "codekavach.core.models.taxonomy",
        "codekavach.core.models.text",
        "codekavach.core.models.timeutil",
        "codekavach.core.models.verdict",
    }
)

# Modules that exist for reasons other than the architecture tree.
ALLOWED_EXTRA_MODULES: frozenset[str] = frozenset(
    {
        "codekavach.__main__",
        "codekavach.cli._version",
        "codekavach.cli.app",
        "codekavach.cli.backends",
        "codekavach.cli.console",
        "codekavach.cli.context",
        "codekavach.cli.errors",
        "codekavach.cli.exit_codes",
        "codekavach.cli.ledger",
        "codekavach.cli.options",
        "codekavach.cli.output",
        "codekavach.cli.privacy",
        "codekavach.cli.scan",
        "codekavach.cli.term_check",
    }
)

# Packages whose __init__.py may import. Add a package here in the same commit
# that gives it a deliberate public API.
INIT_IMPORT_ALLOWLIST: frozenset[str] = frozenset(
    {"codekavach", "codekavach.config", "codekavach.core.log", "codekavach.core.models"}
)

SRC_ROOT = Path(codekavach.__file__).parent


def _discover() -> tuple[set[str], set[str]]:
    packages = {"codekavach"}
    modules: set[str] = set()
    for info in pkgutil.walk_packages(codekavach.__path__, "codekavach."):
        (packages if info.ispkg else modules).add(info.name)
    return packages, modules


def _init_file(package: str) -> Path:
    return SRC_ROOT.joinpath(*package.split(".")[1:], "__init__.py")


def test_packages_match_architecture() -> None:
    packages, _ = _discover()
    missing = EXPECTED_PACKAGES - packages
    unexpected = packages - EXPECTED_PACKAGES
    assert not missing and not unexpected, (
        f"missing packages: {sorted(missing)}; "
        f"unexpected packages: {sorted(unexpected)}; {ADR_HINT}"
    )


def test_modules_match_architecture() -> None:
    _, modules = _discover()
    allowed = EXPECTED_MODULES | ALLOWED_EXTRA_MODULES
    missing = EXPECTED_MODULES - modules
    unexpected = modules - allowed
    assert not missing and not unexpected, (
        f"missing modules: {sorted(missing)}; unexpected modules: {sorted(unexpected)}; {ADR_HINT}"
    )


@pytest.mark.parametrize("name", sorted((EXPECTED_PACKAGES - {"codekavach"}) | EXPECTED_MODULES))
def test_docstring_names_owning_epic(name: str) -> None:
    module: ModuleType = importlib.import_module(name)
    assert module.__doc__, f"{name} has no docstring"
    assert "Owning epic:" in module.__doc__
    assert len([p for p in module.__doc__.split("\n\n") if p.strip()]) >= 2


def _imported_modules(tree: ast.Module, package: str) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names.append(
                    package + "." + (node.module or "") if node.level == 1 else "<relative>"
                )
            else:
                names.append(node.module or "")
    return names


@pytest.mark.parametrize("package", sorted(EXPECTED_PACKAGES))
def test_init_files_do_not_import(package: str) -> None:
    tree = ast.parse(_init_file(package).read_text(encoding="utf-8"))
    imported = _imported_modules(tree, package)
    if package == "codekavach":
        assert all(name == "importlib.metadata" for name in imported), imported
    elif package in INIT_IMPORT_ALLOWLIST:
        assert all(name.startswith(package + ".") for name in imported), imported
    else:
        assert not imported, f"{package}/__init__.py must not import anything: {imported}"
