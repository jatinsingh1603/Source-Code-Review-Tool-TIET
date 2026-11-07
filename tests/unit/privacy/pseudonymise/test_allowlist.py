"""The bundled public-name allowlist: versions, data headers and the extra setting (E09-02)."""

import importlib.resources
import tomllib

import pytest

from codekavach.config import Settings
from codekavach.core.models import Language
from codekavach.privacy.pseudonymise.allowlist import (
    DATA_PACKAGE,
    NoAllowlistError,
    PublicAllowlist,
)


def _data_text(filename: str) -> str:
    return (importlib.resources.files(DATA_PACKAGE) / filename).read_text(encoding="utf-8")


@pytest.mark.parametrize("filename", ["python.toml", "javascript.toml"])
def test_each_data_file_header_records_source_generation_and_version(filename: str) -> None:
    header = _data_text(filename).splitlines()[:12]
    joined = "\n".join(header)
    assert "# Source:" in joined
    assert "# Generated:" in joined
    assert "# Version:" in joined


def test_the_bundled_version_is_the_version_key_of_the_data_file() -> None:
    data = tomllib.loads(_data_text("python.toml"))
    assert PublicAllowlist.bundled(Language.PYTHON).version() == data["version"]


def test_typescript_shares_the_javascript_allowlist() -> None:
    javascript = PublicAllowlist.bundled(Language.JAVASCRIPT)
    typescript = PublicAllowlist.bundled(Language.TYPESCRIPT)
    assert typescript.version() == javascript.version()
    assert typescript.is_public_module("express")


def test_a_language_without_a_bundled_allowlist_is_refused() -> None:
    with pytest.raises(NoAllowlistError):
        PublicAllowlist.bundled(Language.UNKNOWN)


def test_extra_names_are_recorded_by_count_in_the_version() -> None:
    plain = PublicAllowlist.bundled(Language.PYTHON)
    widened = PublicAllowlist.bundled(Language.PYTHON, extra=["festival_bonus_rate"])
    assert "+extra" not in plain.version()
    assert widened.version() == f"{plain.version()}+extra1"
    assert widened.is_extra("festival_bonus_rate")


def test_extra_names_are_read_from_the_settings_key() -> None:
    settings = Settings.model_validate({"privacy": {"public_allowlist_extra": ["festival_rate"]}})
    allowlist = PublicAllowlist.from_settings(Language.PYTHON, settings)
    assert allowlist.is_extra("festival_rate")


def test_extra_names_cannot_remove_bundled_public_names() -> None:
    plain = PublicAllowlist.bundled(Language.PYTHON)
    widened = PublicAllowlist.bundled(Language.PYTHON, extra=["get", "str"])
    assert widened.is_keyword_or_builtin("str")
    assert widened.is_framework_contract("get")
    assert widened.members_of("flask") == plain.members_of("flask")
    assert widened.is_public_module("flask") == plain.is_public_module("flask")
    assert widened.packages_listing("request") == plain.packages_listing("request")


def test_a_third_party_module_is_public_only_when_listed() -> None:
    allowlist = PublicAllowlist.bundled(Language.PYTHON)
    assert allowlist.is_public_module("flask")
    assert allowlist.is_public_module("requests")
    assert not allowlist.is_public_module("billing")
    # A standard-library module is public by its origin, not by this list.
    assert allowlist.kind_of("os") == "stdlib"


def test_the_framework_entries_name_their_framework() -> None:
    data = tomllib.loads(_data_text("python.toml"))
    for section in ("framework_contracts", "framework_decorators"):
        entries = data[section]
        assert entries
        for name, framework in entries.items():
            assert isinstance(framework, str) and framework.strip(), (section, name)


def test_the_javascript_framework_entries_name_their_framework() -> None:
    data = tomllib.loads(_data_text("javascript.toml"))
    for section in ("framework_contracts", "framework_decorators"):
        for name, framework in data[section].items():
            assert isinstance(framework, str) and framework.strip(), (section, name)


def test_is_public_is_the_spelling_only_test_the_literal_shaper_uses() -> None:
    allowlist = PublicAllowlist.bundled(Language.PYTHON, extra=("festival_rate",))
    assert allowlist.is_public("print")  # a builtin
    assert allowlist.is_public("__init__")  # a dunder
    assert allowlist.is_public("festival_rate")  # a name the user added
    assert not allowlist.is_public("compute_bonus")
    assert not allowlist.is_public("flask")  # a module needs the symbol table, not the spelling
