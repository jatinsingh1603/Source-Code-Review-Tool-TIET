"""Static checks of the deployment files (E39-02).

The build context filter is a privacy control: a state directory, vault, ledger or .env file that
reaches the build context can end up in an image layer. These tests pin each exclusion and the
safety properties of the Dockerfile, the compose stack and the Helm values.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
DOCKERIGNORE = ROOT / ".dockerignore"
DOCKERFILE = ROOT / "deploy" / "docker" / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
HELM_VALUES = ROOT / "deploy" / "helm" / "codekavach" / "values.yaml"

pytestmark = pytest.mark.unit

REQUIRED_EXCLUSIONS = (
    ".git",
    ".venv",
    ".env",
    ".env.*",
    ".codekavach",
    "**/.codekavach",
    "**/*.vault",
    "**/*.ledger.jsonl",
    "**/*.pem",
    "**/*.key",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
    "dist",
    "ui/node_modules",
    "ui/dist",
    "tests",
    "eval-data",
)


def _ignore_lines() -> list[str]:
    lines = DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


@pytest.mark.parametrize("pattern", REQUIRED_EXCLUSIONS)
def test_dockerignore_excludes(pattern: str) -> None:
    assert pattern in _ignore_lines()


def test_dockerignore_reincludes_only_safe_paths() -> None:
    reincluded = {line for line in _ignore_lines() if line.startswith("!")}
    assert reincluded == {"!.env.example", "!docs/schemas", "!fixtures/kavachbank"}


def test_every_base_image_is_pinned_by_digest() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    images = re.findall(r"^ARG \w+_IMAGE=(\S+)$", text, re.MULTILINE)
    assert len(images) == 3
    for image in images:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), image
    for line in re.findall(r"^FROM (\S+)", text, re.MULTILINE):
        assert line.startswith("${"), f"FROM {line} bypasses the pinned ARG"


def test_runtime_is_non_root_with_http_healthcheck() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    runtime = text.split("AS runtime", 1)[1]
    assert re.search(r"^USER 10001:10001$", runtime, re.MULTILINE)
    assert "/api/v1/health" in runtime.split("HEALTHCHECK", 1)[1]
    assert '"serve", "--host", "0.0.0.0", "--port", "8080", "--data-dir", "/data"' in runtime
    assert "build-essential" not in runtime
    assert "gcc" not in runtime


def test_compose_holds_no_secret_value_and_binds_localhost() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service = compose["services"]["codekavach"]
    assert service["ports"][0].startswith("${CODEKAVACH_BIND:-127.0.0.1}:")
    assert service["read_only"] is True
    env = service["environment"]
    # Secrets are interpolated from .env at run time, never written in the file.
    assert env["CODEKAVACH_AGENTROUTER_API_KEY"] == "${CODEKAVACH_AGENTROUTER_API_KEY:-}"
    ollama = compose["services"]["ollama"]
    assert ollama["profiles"] == ["local-llm"]
    assert ollama["environment"]["OLLAMA_NO_CLOUD"] == "1"
    assert compose["networks"]["airgap"]["internal"] is True


def test_env_example_has_no_provider_key() -> None:
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.startswith("CODEKAVACH_AGENTROUTER_API_KEY="):
            assert line == "CODEKAVACH_AGENTROUTER_API_KEY="
            return
    pytest.fail("CODEKAVACH_AGENTROUTER_API_KEY is not documented in .env.example")


def test_helm_values_reference_secrets_only() -> None:
    values = yaml.safe_load(HELM_VALUES.read_text(encoding="utf-8"))
    assert values["secrets"]["existingSecret"]
    assert all(set(key) == {"name", "optional"} for key in values["secrets"]["keys"])
    assert values["securityContext"]["readOnlyRootFilesystem"] is True
    assert values["podSecurityContext"]["runAsNonRoot"] is True
    assert values["networkPolicy"]["enabled"] is True
