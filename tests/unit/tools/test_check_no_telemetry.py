"""The telemetry-free dependency guard (E01-31)."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools/dev/check_no_telemetry.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_no_telemetry", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_no_telemetry"] = module
    spec.loader.exec_module(module)
    return module


tel = _load()
POLICY = tel.Policy.from_table({"deny": ["sentry-sdk", "opentelemetry-exporter-*", "posthog"]})
COMPLETE = {
    "reason": "transitive; never initialised",
    "verified_by": "tests/x.py",
    "approved_in": "#1",
}


def lock(*packages: tuple[str, str]) -> str:
    body = "".join(
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n\n' for name, version in packages
    )
    return f"version = 1\n\n{body}"


def test_exact_wildcard_and_non_match() -> None:
    text = lock(
        ("sentry-sdk", "2.0"),
        ("opentelemetry-exporter-otlp", "1.2"),
        ("opentelemetry-api", "1.2"),
        ("pydantic", "2.9"),
    )
    hits = tel.telemetry_packages(text, POLICY)
    assert [(h.package, h.pattern) for h in hits] == [
        ("opentelemetry-exporter-otlp", "opentelemetry-exporter-*"),
        ("sentry-sdk", "sentry-sdk"),
    ]
    assert not any(h.excepted for h in hits)


def test_name_normalisation() -> None:
    hits = tel.telemetry_packages(lock(("Sentry_SDK", "2.0"), ("PostHog", "3")), POLICY)
    assert [h.package for h in hits] == ["posthog", "sentry-sdk"]


def test_complete_and_incomplete_exceptions() -> None:
    incomplete = {"reason": "x", "approved_in": "#1"}
    policy = tel.Policy.from_table(
        {
            "deny": ["sentry-sdk", "posthog"],
            "exceptions": {"Sentry-SDK": COMPLETE, "posthog": incomplete},
        }
    )
    hits = {
        h.package: h
        for h in tel.telemetry_packages(lock(("sentry-sdk", "2"), ("posthog", "3")), policy)
    }
    assert hits["sentry-sdk"].excepted
    assert not hits["posthog"].excepted
    assert hits["posthog"].problem == "exception lacks verified_by"


def test_stale_exception() -> None:
    policy = tel.Policy.from_table({"deny": ["sentry-sdk"], "exceptions": {"gone": COMPLETE}})
    assert tel.stale_exceptions(lock(("pydantic", "2")), policy) == ["gone"]


@pytest.mark.parametrize(
    "table", [None, {}, {"deny": "sentry-sdk"}, {"deny": [], "exceptions": []}]
)
def test_malformed_policy(table: object) -> None:
    with pytest.raises(tel.PolicyError):
        tel.Policy.from_table(table)


def write(tmp_path: Path, lock_text: str, exceptions: str = "") -> list[str]:
    (tmp_path / "uv.lock").write_text(lock_text, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        f'[tool.codekavach.telemetry]\ndeny = ["sentry-sdk"]\n'
        f"[tool.codekavach.telemetry.exceptions]\n{exceptions}",
        encoding="utf-8",
    )
    return ["--lock", str(tmp_path / "uv.lock"), "--pyproject", str(tmp_path / "pyproject.toml")]


def test_cli_fails_names_the_package_and_accepts_an_exception(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = lock(("sentry-sdk", "2.1"), ("rich", "13"))
    assert tel.main(write(tmp_path, text)) == 1
    assert "sentry-sdk 2.1 matches sentry-sdk" in capsys.readouterr().err
    entry = '"sentry-sdk" = { reason = "r", verified_by = "tests/t.py", approved_in = "#9" }\n'
    assert tel.main(write(tmp_path, text, entry)) == 0
    assert "exception: sentry-sdk 2.1" in capsys.readouterr().out
    half = '"sentry-sdk" = { reason = "r", approved_in = "#9" }\n'
    assert tel.main(write(tmp_path, text, half)) == 1
    assert "lacks verified_by" in capsys.readouterr().err


def test_cli_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = write(tmp_path, "this is [ not toml")
    assert tel.main(args) == 2
    (tmp_path / "uv.lock").write_text(lock(("rich", "13")), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[tool]\n", encoding="utf-8")
    assert tel.main(args) == 2
    assert tel.main(["--lock", str(tmp_path / "missing.lock"), "--pyproject", args[3]]) == 2
    assert "cannot check" in capsys.readouterr().err


def test_repository_lockfile_is_clean() -> None:
    assert tel.main([]) == 0
