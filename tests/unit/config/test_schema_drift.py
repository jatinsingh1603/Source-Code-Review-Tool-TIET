"""The committed configuration schemas match the models (E03-38)."""

from pathlib import Path

import pytest

from codekavach.config.schema import (
    POLICY_FILE,
    SETTINGS_FILE,
    dump_schema,
    policy_schema,
    settings_schema,
)
from tests.support.cli import run_cli

SCHEMAS = Path(__file__).resolve().parents[3] / "docs" / "schemas"
REFRESH = {
    SETTINGS_FILE: f"uv run codekavach config schema --output docs/schemas/{SETTINGS_FILE}",
    POLICY_FILE: f"uv run codekavach config schema --policy --output docs/schemas/{POLICY_FILE}",
}


@pytest.mark.parametrize(
    ("name", "build"), [(SETTINGS_FILE, settings_schema), (POLICY_FILE, policy_schema)]
)
def test_committed_schema_is_current(name: str, build: object) -> None:
    expected = dump_schema(build())  # type: ignore[operator]
    committed = (SCHEMAS / name).read_bytes()
    assert committed == expected.encode("utf-8"), f"{name} is stale; run: {REFRESH[name]}"


@pytest.mark.parametrize(("name", "args"), [(SETTINGS_FILE, []), (POLICY_FILE, ["--policy"])])
def test_cli_prints_the_committed_bytes(name: str, args: list[str]) -> None:
    result = run_cli(["config", "schema", *args])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.encode("utf-8") == (SCHEMAS / name).read_bytes()
