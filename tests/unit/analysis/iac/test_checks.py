"""Native IaC checks fire on planted misconfigurations and stay quiet on safe files (issue 239)."""

import pytest

from codekavach.analysis.iac.stage import candidates_for, checkers_for
from codekavach.core.models import Language
from tests.support.kavachbank import FIXTURE_ROOT


def _rules(rel: str) -> set[str]:
    text = (FIXTURE_ROOT / rel).read_text()
    return {i.rule for check in checkers_for(rel, text) for i in check(text)}


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        (
            "deploy/Dockerfile",
            {
                "iac.docker.root-user",
                "iac.docker.unpinned-base-image",
                "iac.docker.add-remote-url",
                "iac.docker.secret-in-env",
            },
        ),
        (
            "deploy/docker-compose.yml",
            {"iac.compose.privileged", "iac.compose.host-network", "iac.compose.docker-socket"},
        ),
        (
            "deploy/k8s/api.yaml",
            {"iac.k8s.privileged", "iac.k8s.host-path", "iac.k8s.no-limits", "iac.k8s.run-as-root"},
        ),
        (
            "infra/main.tf",
            {
                "iac.terraform.s3-public-acl",
                "iac.terraform.open-security-group",
                "iac.terraform.unencrypted-storage",
            },
        ),
        (
            ".github/workflows/ci.yml",
            {
                "iac.actions.pull-request-target-checkout",
                "iac.actions.script-injection",
                "iac.actions.unpinned-action",
                "iac.actions.write-all-permissions",
            },
        ),
        (
            "services/api/settings.yaml",
            {
                "iac.appconfig.debug-enabled",
                "iac.appconfig.cors-wildcard",
                "iac.appconfig.tls-verification-disabled",
                "iac.appconfig.weak-tls-version",
            },
        ),
    ],
)
def test_planted_misconfigurations_are_found(rel: str, expected: set[str]) -> None:
    assert expected <= _rules(rel)


def test_safe_dockerfile_is_clean() -> None:
    text = "FROM python:3.12-slim@sha256:" + "a" * 64 + "\nRUN useradd app\nUSER app\n"
    assert checkers_for("Dockerfile", text)[0](text) == []


def test_safe_workflow_is_clean() -> None:
    text = (
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@" + "b" * 40 + "\n"
        '      - run: echo "$TITLE"\n        env:\n'
        "          TITLE: ${{ github.event.issue.title }}\n"
    )
    check = checkers_for(".github/workflows/x.yml", text)[0]
    assert check(text) == []


def test_candidates_never_quote_values() -> None:
    rel = "deploy/Dockerfile"
    text = (FIXTURE_ROOT / rel).read_text()
    issues = [i for c in checkers_for(rel, text) for i in c(text)]
    built = candidates_for(rel, Language.DOCKERFILE, text, issues)
    assert built
    assert "changeme-in-prod" not in "".join(c.model_dump_json() for c in built)


def test_every_manifest_misconfiguration_is_reported_at_its_line() -> None:
    from tests.support.kavachbank import load_manifest  # noqa: PLC0415

    for item in load_manifest().planted_misconfigurations:
        text = (FIXTURE_ROOT / item.file).read_text()
        found = {(i.rule, i.line) for c in checkers_for(item.file, text) for i in c(text)}
        assert (item.rule, item.line) in found, item.id
