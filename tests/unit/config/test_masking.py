import copy
import json
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config import Settings, mask_settings
from codekavach.config.masking import MASK, mask_layer_data
from tests.support.config_strategies import settings_dicts
from tests.support.synthetic import SECRET_SHAPES, example_secret


def example_settings() -> tuple[Settings, str]:
    value = example_secret("anthropic_api_key")
    data = {
        "privacy": {"domain_terms": ["kavachbank", "accrual"]},
        "llm": {"providers": {"lab": {"kind": "mock", "options": {"note": value}}}},
    }
    return Settings.model_validate(data), value


def test_example_masks_terms_and_key() -> None:
    s, value = example_settings()
    masked = mask_settings(s)
    text = json.dumps(masked)
    for hidden in ("kavachbank", "accrual", value):
        assert hidden not in text
    assert masked["privacy"]["domain_terms"] == ["<2 hidden>"]
    assert masked["llm"]["providers"]["lab"]["options"] == {"note": MASK}


def test_reveal_domain_terms_keeps_key_masked() -> None:
    s, value = example_settings()
    text = json.dumps(mask_settings(s, reveal_domain_terms=True))
    assert "kavachbank" in text
    assert "accrual" in text
    assert value not in text


def test_defaults_unchanged() -> None:
    assert mask_settings(Settings()) == Settings().model_dump(mode="json")


def test_input_not_mutated() -> None:
    s, _ = example_settings()
    before = s.model_dump(mode="json")
    mask_settings(s)
    assert s.model_dump(mode="json") == before
    data = {"llm": {"providers": {"x": {"options": {"a": [example_secret("github_token")]}}}}}
    snapshot = copy.deepcopy(data)
    result = mask_layer_data(data)
    assert data == snapshot
    assert result is not data
    assert result["llm"] is not data["llm"]


# rules


def test_sensitive_string_and_profile_overlay() -> None:
    masked = mask_layer_data(
        {
            "privacy": {"domain_terms": "kavachbank,accrual"},
            "profiles": {"ci": {"privacy": {"domain_terms": ["kavachbank"]}}},
        }
    )
    assert masked["privacy"]["domain_terms"] == MASK
    assert masked["profiles"]["ci"]["privacy"]["domain_terms"] == ["<1 hidden>"]


def test_value_detector_in_nested_options_and_lists() -> None:
    value = example_secret("github_token")
    data = {
        "llm": {"providers": {"lab": {"options": {"deep": {"args": ["--flag", value, 3, True]}}}}}
    }
    args = mask_layer_data(data)["llm"]["providers"]["lab"]["options"]["deep"]["args"]
    assert args == ["--flag", MASK, 3, True]


def test_non_string_leaves_untouched() -> None:
    data = {"scan": {"jobs": 4, "respect_gitignore": False, "note": None}}
    assert mask_layer_data(data) == data


def test_userinfo_removed_from_url() -> None:
    url = example_secret("basic_auth_url")
    masked = mask_layer_data({"llm": {"providers": {"lab": {"base_url": url}}}})
    shown = masked["llm"]["providers"]["lab"]["base_url"]
    assert "@" not in shown
    assert shown.startswith("https://")
    assert url != shown
    assert mask_layer_data({"u": "https://" + "user:" + "pw" + "@host.example.test/v1"}) == {
        "u": "https://host.example.test/v1"
    }


def test_plain_url_kept() -> None:
    assert mask_layer_data({"u": "https://host.example.test/v1"}) == {
        "u": "https://host.example.test/v1"
    }


@pytest.mark.parametrize(
    "ref",
    [
        # pragma: allowlist nextline secret
        "env:ANTHROPIC_API_KEY",
        "keyring:codekavach/primary",
        "file:~/secrets/key.txt",
    ],
)
def test_secret_references_shown(ref: str) -> None:
    data = {"llm": {"providers": {"p": {"api_key": ref}}}}
    assert mask_layer_data(data) == data


# properties

_terms = st.lists(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=10).map(
        lambda word: "zq" + word
    ),
    min_size=1,
    max_size=5,
)


@given(settings_dicts(), _terms)
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_domain_terms_never_in_output(data: dict[str, Any], terms: list[str]) -> None:
    data.setdefault("privacy", {})["domain_terms"] = terms
    text = json.dumps(mask_settings(Settings.model_validate(data)))
    for term in terms:
        assert term not in text


_segments = st.lists(st.sampled_from(["note", "extra", "misc", "deep"]), min_size=1, max_size=3)


@given(st.sampled_from(sorted(SECRET_SHAPES)), _segments)
def test_synthetic_secrets_never_in_output(kind: str, path: list[str]) -> None:
    value = example_secret(kind)
    options: dict[str, Any] = {}
    node = options
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value
    data = {"llm": {"providers": {"lab": {"kind": "mock", "options": options}}}}
    assert value not in json.dumps(mask_layer_data(data))
