"""The import contracts exist, are well formed and grant only the one I1 exception."""

import configparser
import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACTS = (
    "i1-single-egress",
    "i2-llm-no-raw-code",
    "i3-vault-locality",
    "core-models-independent",
    "config-is-a-leaf",
)


def _config() -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read(REPO_ROOT / ".importlinter", encoding="utf-8")
    return parser


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def test_contracts_exist() -> None:
    config = _config()
    for name in CONTRACTS:
        assert config.has_section(f"importlinter:contract:{name}"), name


def test_external_packages_included() -> None:
    assert _config().getboolean("importlinter", "include_external_packages")


def test_transport_is_the_only_ignore_source() -> None:
    config = _config()
    sources = set()
    for section in config.sections():
        if config.has_option(section, "ignore_imports"):
            for line in _lines(config.get(section, "ignore_imports")):
                sources.add(line.split("->")[0].strip())
    assert sources == {"codekavach.privacy.egress.transport"}


def _internal_modules() -> set[str]:
    config = _config()
    names: set[str] = set()
    for section in config.sections():
        for option in ("source_modules", "forbidden_modules", "ignore_imports"):
            if config.has_option(section, option):
                for line in _lines(config.get(section, option)):
                    names.update(
                        part.strip()
                        for part in line.split("->")
                        if part.strip().startswith("codekavach")
                    )
    return names


@pytest.mark.parametrize("module", sorted(_internal_modules()))
def test_internal_modules_are_importable(module: str) -> None:
    importlib.import_module(module)
