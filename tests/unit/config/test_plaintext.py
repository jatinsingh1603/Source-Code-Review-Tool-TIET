import base64
import random
import tomllib
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.config.errors import PlaintextSecretError
from codekavach.config.overrides import parse_set_options
from codekavach.config.plaintext import (
    SECRET_KEY_NAME,
    VALUE_DETECTORS,
    find_plaintext_secrets,
    shannon_entropy,
)
from tests.support.config import ConfigSandbox, to_toml
from tests.support.config_strategies import settings_dicts
from tests.support.synthetic import AWS_EXAMPLE_ACCESS_KEY_ID, example_secret

SRC = Path(__file__).resolve().parents[3] / "src"


def detectors_of(data: dict[str, Any]) -> list[str]:
    issues = find_plaintext_secrets(data, source="test.toml", text=None)
    return [issue.message.split("detector: ")[1].split(",")[0] for issue in issues]


POSITIVES = {
    "anthropic-key": example_secret("anthropic_api_key"),
    "openai-key": example_secret("openai_project_key"),
    "google-api-key": example_secret("google_api_key"),
    "xai-key": example_secret("xai_api_key"),
    "aws-access-key-id": AWS_EXAMPLE_ACCESS_KEY_ID,
    "github-token": example_secret("github_token"),
    "jwt": example_secret("jwt"),
    "pem-private-key": example_secret("private_key"),
    "url-credentials": example_secret("basic_auth_url"),
}
NEAR_MISSES = {
    "anthropic-key": "s" + "k-ant-short",
    "openai-key": "s" + "k-" + "a" * 10,
    "google-api-key": "AI" + "za" + "x" * 20,
    "xai-key": "xa" + "i-short",
    "aws-access-key-id": "AK" + "IA" + "ABC",
    "github-token": "gh" + "p_short",
    "jwt": "ey" + "Jshort.abc.def",
    "pem-private-key": "-----BEG" + "IN PUBLIC KEY-----",
    "url-credentials": "https://host.example.test/v1",
}


def test_detectors_cover_the_table() -> None:
    assert [d.id for d in VALUE_DETECTORS] == list(POSITIVES)


@pytest.mark.parametrize("detector", list(POSITIVES))
def test_positive_per_detector(detector: str) -> None:
    assert detectors_of({"notes": {"text": POSITIVES[detector]}}) == [detector]


@pytest.mark.parametrize("detector", list(NEAR_MISSES))
def test_near_miss_per_detector(detector: str) -> None:
    assert detectors_of({"notes": {"text": NEAR_MISSES[detector]}}) == []


# rule C


def _random_base64(length: int) -> str:
    rng = random.Random(7)  # noqa: S311 - reproducible test data
    return base64.b64encode(rng.randbytes(length)).decode()[:length]


def test_high_entropy_in_free_form_table() -> None:
    value = _random_base64(64)
    assert shannon_entropy(value) >= 4.0
    data = {"llm": {"providers": {"lab": {"kind": "mock", "options": {"note": value}}}}}
    assert detectors_of(data) == ["high-entropy"]


@pytest.mark.parametrize(
    "value",
    [
        "/very/long/path/to/some/deeply/nested/directory/file.txt",
        "https://example.test/a/very/long/url/path/without/credentials/inside",
        "a-lower-case-sentence-without-spaces-ok",
    ],
)
def test_high_entropy_negatives(value: str) -> None:
    data = {"llm": {"providers": {"lab": {"kind": "mock", "options": {"note": value}}}}}
    assert detectors_of(data) == []


def test_high_entropy_ignored_in_typed_field() -> None:
    assert detectors_of({"project": {"description": _random_base64(64)}}) == []


# rule A


@pytest.mark.parametrize(
    "name", ["api_key", "apikey", "client_secret", "webhook_secret", "github_token"]
)
def test_secret_key_names_match(name: str) -> None:
    assert SECRET_KEY_NAME.search(name)
    assert detectors_of({"x": {name: "value"}}) == ["secret-key-name"]


@pytest.mark.parametrize("name", ["max_output_tokens", "key_source", "tokeniser", "author"])
def test_non_secret_key_names(name: str) -> None:
    assert not SECRET_KEY_NAME.search(name)


def test_rule_a_reports_matching_shape() -> None:
    value = example_secret("anthropic_api_key")
    assert detectors_of({"x": {"api_key": value}}) == ["anthropic-key"]


@pytest.mark.parametrize(
    "data",
    [
        # pragma: allowlist nextline secret
        {"llm": {"providers": {"p": {"api_key": "env:ANTHROPIC_API_KEY"}}}},
        {"llm": {"max_output_tokens": 2048}},
        {"integrations": {"github": {"labels_prefix": "codekavach"}}},
        {"privacy": {"vault": {"key_source": "keyring"}}},
        {"integrations": {"github": {"token": ""}}},
    ],
)
def test_no_false_positives(data: dict[str, Any]) -> None:
    assert detectors_of(data) == []


def test_nested_lists_and_inline_tables() -> None:
    value = example_secret("github_token")
    data = {"engines": {"options": {"x": {"args": ["--flag", value]}}}}
    issues = find_plaintext_secrets(data, source="s", text=None)
    assert [issue.key for issue in issues] == ["engines.options.x.args[1]"]


# loading


def test_project_file_refused_with_location(
    config_sandbox: ConfigSandbox,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    value = example_secret("anthropic_api_key")
    text = (
        '[llm]\ndefault_provider = "primary"\n\n'
        '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n\n'
        f'[llm.providers.primary.options]\nkey = "{value}"\n'
    )
    path = config_sandbox.write_project(text)
    with pytest.raises(PlaintextSecretError) as info:
        config_sandbox.load()
    issue = info.value.issues[0]
    assert issue.code.value == "CK-CFG-010"
    assert issue.source == str(path)
    assert issue.line == 9
    assert issue.key == "llm.providers.primary.options.key"
    assert "anthropic-key" in issue.message
    assert f"{len(value)} characters" in issue.message
    assert issue.hint is not None
    # pragma: allowlist nextline secret
    assert 'api_key = "env:ANTHROPIC_API_KEY"' in issue.hint
    assert "codekavach config key set primary" in issue.hint
    captured = capsys.readouterr()
    for text_out in (str(info.value), repr(info.value), caplog.text, captured.out, captured.err):
        assert value not in text_out


def test_url_credentials_in_base_url(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_project(
        '[llm.providers.lab]\nkind = "openai-compatible"\nmodel = "m"\n'
        f'base_url = "{example_secret("basic_auth_url")}"\n'
    )
    with pytest.raises(PlaintextSecretError) as info:
        config_sandbox.load()
    assert "url-credentials" in info.value.issues[0].message


def test_environment_and_cli_sources(config_sandbox: ConfigSandbox) -> None:
    value = example_secret("openai_project_key")
    config_sandbox.env["CODEKAVACH_LLM__PROVIDERS__X__API_KEY"] = value
    with pytest.raises(PlaintextSecretError) as info:
        config_sandbox.load()
    assert info.value.issues[0].source == "CODEKAVACH_LLM__PROVIDERS__X__API_KEY"
    del config_sandbox.env["CODEKAVACH_LLM__PROVIDERS__X__API_KEY"]
    overrides = parse_set_options([f'llm.providers.x.api_key="{value}"'])
    with pytest.raises(PlaintextSecretError) as info:
        config_sandbox.load(cli_overrides=overrides)
    assert info.value.issues[0].source == "--set llm.providers.x.api_key"
    assert value not in str(info.value)


def test_unselected_profile_and_two_layers_reported_together(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(
        '[profiles.unused.llm.providers.p]\nkind = "mock"\n'
        f'api_key = "{example_secret("xai_api_key")}"\n'
    )
    config_sandbox.write_project(
        f'[integrations.github]\ntoken = "{example_secret("github_token")}"\n'
    )
    with pytest.raises(PlaintextSecretError) as info:
        config_sandbox.load()
    keys = sorted(issue.key or "" for issue in info.value.issues)
    assert keys == ["integrations.github.token", "profiles.unused.llm.providers.p.api_key"]


def test_no_bypass_switch() -> None:
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        assert "allow_plaintext" not in text and "allow-plaintext" not in text, path


# properties

_KINDS = [
    "anthropic_api_key",
    "openai_project_key",
    "google_api_key",
    "xai_api_key",
    "github_token",
    "jwt",
]
_segments = st.lists(st.sampled_from(["alpha", "notes", "extra", "misc"]), min_size=1, max_size=3)


@given(st.sampled_from(_KINDS), _segments)
def test_embedded_secret_never_in_error(kind: str, path: list[str]) -> None:
    value = example_secret(kind)
    data: dict[str, Any] = {}
    node = data
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value
    issues = find_plaintext_secrets(data, source="s", text=to_toml(data))
    assert issues
    for issue in issues:
        assert value not in repr(issue)


@given(settings_dicts())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_valid_configurations_report_nothing(data: dict[str, Any]) -> None:
    assert find_plaintext_secrets(data, source="s", text=None) == []


def test_defaults_and_builtin_profiles_report_nothing() -> None:
    defaults = Settings().model_dump(mode="json")
    assert find_plaintext_secrets(defaults, source="defaults", text=None) == []
    profile_dir = SRC / "codekavach" / "config" / "builtin_profiles"
    for path in profile_dir.glob("*.toml"):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        assert find_plaintext_secrets(data, source=str(path), text=None) == [], path
