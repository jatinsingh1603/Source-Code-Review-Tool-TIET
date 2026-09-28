import json
import tomllib
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.config.loader import LoadedConfig
from codekavach.config.provenance import Layer, Origin
from codekavach.config.render import render_json, render_layer, render_toml
from tests.support.config_strategies import settings_dicts
from tests.support.synthetic import example_secret


def loaded_of(data: dict[str, Any], **extra: Any) -> LoadedConfig:
    return LoadedConfig(
        settings=Settings.model_validate(data),
        origins={},
        layers=(),
        project_root=Path(),
        **extra,
    )


def test_defaults_round_trip() -> None:
    text = render_toml(loaded_of({}), origins=True, section=None)
    assert Settings.model_validate(tomllib.loads(text)) == Settings()


@given(settings_dicts())
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_generated_round_trip(data: dict[str, Any]) -> None:
    data.get("privacy", {}).pop("domain_terms", None)  # masked values cannot round-trip
    loaded = loaded_of(data)
    text = render_toml(loaded, origins=False, section=None)
    assert Settings.model_validate(tomllib.loads(text)) == loaded.settings
    json.loads(render_json(loaded, section=None))


_terms = st.lists(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=10).map(lambda w: "zq" + w),
    min_size=1,
    max_size=5,
)


@given(settings_dicts(), _terms)
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_domain_terms_never_rendered(data: dict[str, Any], terms: list[str]) -> None:
    data.setdefault("privacy", {})["domain_terms"] = terms
    loaded = loaded_of(data)
    rendered = render_toml(loaded, origins=True, section=None) + render_json(loaded, section=None)
    for term in terms:
        assert term not in rendered


def test_reveal_domain_terms() -> None:
    loaded = loaded_of({"privacy": {"domain_terms": ["kavachbank"]}})
    assert "kavachbank" in render_toml(
        loaded, origins=False, section=None, reveal_domain_terms=True
    )
    assert "kavachbank" in render_json(loaded, section=None, reveal_domain_terms=True)


def test_origin_comments_and_locks() -> None:
    origins = {
        "privacy.level": Origin(layer="user", source="/home/u/config.toml", line=2),
        "privacy.domain_terms": Origin(
            layer="project",
            source="/repo/codekavach.toml",
            line=9,
            contributors=("project", "project:file"),
        ),
        "privacy.min_level": Origin(layer="org-policy", source="/etc/codekavach/policy.toml"),
    }
    loaded = LoadedConfig(
        settings=Settings.model_validate({"privacy": {"level": "L4", "domain_terms": ["ab"]}}),
        origins=origins,
        layers=(),
        project_root=Path(),
        locked_keys=frozenset({"privacy.min_level"}),
    )
    text = render_toml(loaded, origins=True, section="privacy")
    assert "# user: /home/u/config.toml:2" in text
    assert "# project: /repo/codekavach.toml:9 (+ project:file)" in text
    assert "# org-policy (locked): /etc/codekavach/policy.toml" in text
    assert "[scan]" not in text


def test_render_layer_masks() -> None:
    value = example_secret("github_token")
    layer = Layer(name="env", source="env", data={"integrations": {"github": {"note": value}}})
    for fmt in ("toml", "json"):
        assert value not in render_layer(layer, fmt=fmt)
