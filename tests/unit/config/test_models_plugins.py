import pytest
from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.models.plugins import PluginsSettings, normalise_distribution


def test_defaults_and_restricted_marker() -> None:
    plugins = PluginsSettings()
    assert plugins.allow_distributions == []
    assert plugins.disable == []
    properties = Settings.model_json_schema()["$defs"]["PluginsSettings"]["properties"]
    assert properties["allow_distributions"]["x-ck-restricted"] is True
    assert properties["disable"]["x-ck-restricted"] is True


@pytest.mark.parametrize("entry", ["semgrep", "stage:privacy-prepare", "stage:restore", "Engine:x"])
def test_disable_rejected(entry: str) -> None:
    with pytest.raises(ValidationError) as info:
        PluginsSettings(disable=[entry])
    assert str(info.value.errors()[0]["ctx"]["error"]).startswith("[CK-CFG-003]")


def test_privacy_stage_refusal_names_the_alternative() -> None:
    with pytest.raises(ValidationError) as info:
        PluginsSettings(disable=["stage:privacy-prepare"])
    assert "llm.enabled = false" in str(info.value.errors()[0]["ctx"]["error"])


def test_disable_accepted() -> None:
    assert PluginsSettings(disable=["engine:semgrep", "stage:sync"]).disable == [
        "engine:semgrep",
        "stage:sync",
    ]


@pytest.mark.parametrize("name", ["-bad", "a b", "x" * 101, ""])
def test_distribution_pattern(name: str) -> None:
    with pytest.raises(ValidationError):
        PluginsSettings(allow_distributions=[name])


def test_distribution_normalisation() -> None:
    assert normalise_distribution("CodeKavach_Extra.Plugins") == "codekavach-extra-plugins"
    parsed = PluginsSettings.model_validate({"allow_distributions": "a-b, c.d"})
    assert parsed.allow_distributions == ["a-b", "c.d"]
