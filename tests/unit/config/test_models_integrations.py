import re
import tomllib
from typing import Any

import pytest
from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.models.integrations import GitHubSettings, IntegrationsSettings, McpSettings
from codekavach.core.models import Severity

EXAMPLE = """
[integrations.github]
enabled = true
repository = "examplebank/payments-api"
token = "env:GITHUB_TOKEN"
issue_sync = true
project_owner = "examplebank"
project_number = 4
"""


def message(error: ValidationError) -> str:
    details = error.errors()[0]
    return str(details.get("ctx", {}).get("error", details["msg"]))


def test_defaults_are_inert() -> None:
    github = Settings().integrations.github
    assert github.enabled is False
    assert github.dry_run is True
    assert not (github.issue_sync or github.sarif_upload or github.checks)
    assert github.close_resolved is True
    assert github.min_severity_for_issues is Severity.MEDIUM
    assert github.max_issues_per_run == 50
    assert github.labels_prefix == "codekavach"
    assert str(github.api_url) == "https://api.github.com/"
    assert github.token is None
    mcp = Settings().integrations.mcp
    assert mcp.enabled is False
    assert mcp.transport == "stdio"
    assert mcp.bind == "127.0.0.1:8765"


def test_example_validates() -> None:
    settings = Settings.model_validate(tomllib.loads(EXAMPLE))
    assert settings.integrations.github.project_number == 4


def test_example_without_repository_fails() -> None:
    data = tomllib.loads(EXAMPLE)
    del data["integrations"]["github"]["repository"]
    with pytest.raises(ValidationError) as info:
        Settings.model_validate(data)
    assert message(info.value).startswith("[CK-CFG-036]")


@pytest.mark.parametrize(
    "fields",
    [
        {"issue_sync": True},
        {"sarif_upload": True},
        {"checks": True},
        {"project_number": 1, "project_owner": "o"},
        {"issue_sync": True, "enabled": True},
        {"issue_sync": True, "repository": "a/b"},
        {"enabled": True, "repository": "a/b", "project_number": 1},
    ],
)
def test_prerequisites(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as info:
        GitHubSettings.model_validate(fields)
    assert message(info.value).startswith("[CK-CFG-036]")


def test_prerequisites_met() -> None:
    github = GitHubSettings.model_validate(
        {"enabled": True, "repository": "a/b", "sarif_upload": True, "checks": True}
    )
    assert github.checks


# Assembled at runtime so that no credential-shaped URL literal is committed.
USERINFO_VALUE = "s3" + "cr3t"
CREDENTIAL_URL = "https://user:" + USERINFO_VALUE + "@ghe.example.org/api/v3"


@pytest.mark.parametrize("url", ["http://ghe.example.org/api/v3", CREDENTIAL_URL])
def test_api_url_rejected(url: str) -> None:
    with pytest.raises(ValidationError) as info:
        GitHubSettings.model_validate({"api_url": url})
    text = message(info.value)
    assert text.startswith("[CK-CFG-034]")
    assert "ghe.example.org" in text
    assert USERINFO_VALUE not in text


def test_enterprise_api_url_accepted() -> None:
    github = GitHubSettings.model_validate({"api_url": "https://ghe.example.org/api/v3"})
    assert github.api_url.host == "ghe.example.org"


@pytest.mark.parametrize("repository", ["a/b", "Example-Bank/payments.api", "a_1/b-2"])
def test_repository_accepted(repository: str) -> None:
    assert GitHubSettings(repository=repository).repository == repository


@pytest.mark.parametrize("repository", ["a", "a/b/c", "/a/b", "a/", "a b/c"])
def test_repository_rejected(repository: str) -> None:
    with pytest.raises(ValidationError) as info:
        GitHubSettings(repository=repository)
    assert message(info.value).startswith("[CK-CFG-003]")


@pytest.mark.parametrize("value", [0, 501])
def test_max_issues_bounds(value: int) -> None:
    with pytest.raises(ValidationError):
        GitHubSettings(max_issues_per_run=value)


@pytest.mark.parametrize("prefix", ["", "Upper", "x" * 31, "a_b"])
def test_labels_prefix(prefix: str) -> None:
    with pytest.raises(ValidationError):
        GitHubSettings(labels_prefix=prefix)


@pytest.mark.parametrize("bind", ["127.0.0.1:8765", "localhost:9000", "[::1]:8765"])
def test_mcp_loopback_accepted(bind: str) -> None:
    assert McpSettings(bind=bind).bind == bind


def test_mcp_non_loopback() -> None:
    with pytest.raises(ValidationError):
        McpSettings(bind="0.0.0.0:8765")
    with pytest.raises(ValidationError):
        McpSettings(bind="0.0.0.0:8765", allow_non_loopback=True)
    with pytest.raises(ValidationError):
        McpSettings(bind="0.0.0.0:8765", transport="http")
    allowed = McpSettings(bind="0.0.0.0:8765", transport="http", allow_non_loopback=True)
    assert allowed.allow_non_loopback


@pytest.mark.parametrize("bind", ["8765", "127.0.0.1:", "127.0.0.1:70000", ":80"])
def test_mcp_bind_syntax(bind: str) -> None:
    with pytest.raises(ValidationError):
        McpSettings(bind=bind)


def test_section_is_restricted() -> None:
    schema = Settings.model_json_schema()
    assert schema["properties"]["integrations"]["x-ck-restricted"] is True


def test_no_auto_fix_vocabulary() -> None:
    # Whole word parts, so that labels_prefix does not count as "fix".
    forbidden = re.compile(r"(^|_)(fix|patch)(_|$)|pull_request|auto_merge")
    for model in (IntegrationsSettings, GitHubSettings, McpSettings):
        for name in model.model_fields:
            assert not forbidden.search(name), f"{model.__name__}.{name}"
