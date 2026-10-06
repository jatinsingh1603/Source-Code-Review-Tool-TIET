"""Opt-out environment defaults (E01-31)."""

import importlib
import os
import sys

import pytest

from codekavach.cli import app as cli_app
from codekavach.core import no_telemetry
from codekavach.core.no_telemetry import OPT_OUT_ENV, apply_opt_outs

EXPECTED = {
    "DO_NOT_TRACK",
    "HF_HUB_DISABLE_TELEMETRY",
    "SEMGREP_SEND_METRICS",
    "DOTNET_CLI_TELEMETRY_OPTOUT",
    "SCARF_NO_ANALYTICS",
    "CHECKPOINT_DISABLE",
}


def test_sets_everything_on_an_empty_mapping() -> None:
    environ: dict[str, str] = {}
    applied = apply_opt_outs(environ)
    assert set(applied) == EXPECTED
    assert environ == applied == dict(OPT_OUT_ENV)


def test_existing_values_are_kept_and_not_reported() -> None:
    environ = {"DO_NOT_TRACK": "0", "SEMGREP_SEND_METRICS": "on", "UNRELATED": "x"}
    applied = apply_opt_outs(environ)
    assert environ["DO_NOT_TRACK"] == "0"
    assert environ["SEMGREP_SEND_METRICS"] == "on"
    assert environ["UNRELATED"] == "x"
    assert set(applied) == EXPECTED - {"DO_NOT_TRACK", "SEMGREP_SEND_METRICS"}
    assert apply_opt_outs(environ) == {}


def test_defaults_to_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in EXPECTED:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CHECKPOINT_DISABLE", "keep")
    applied = apply_opt_outs()
    assert set(applied) == EXPECTED - {"CHECKPOINT_DISABLE"}
    assert os.environ["CHECKPOINT_DISABLE"] == "keep"
    assert os.environ["HF_HUB_DISABLE_TELEMETRY"] == "1"


def test_table_shape() -> None:
    assert set(OPT_OUT_ENV) == EXPECTED
    for name, value in OPT_OUT_ENV.items():
        assert name == name.upper()
        assert isinstance(value, str)
        assert value
    with pytest.raises(TypeError):
        OPT_OUT_ENV["NEW"] = "1"  # type: ignore[index]


def test_import_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in EXPECTED:
        monkeypatch.delenv(name, raising=False)
    before = dict(os.environ)
    sys.modules.pop("codekavach.core.no_telemetry", None)
    importlib.import_module("codekavach.core.no_telemetry")
    assert dict(os.environ) == before
    sys.modules["codekavach.core.no_telemetry"] = no_telemetry


def test_main_applies_opt_outs_before_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_apply() -> dict[str, str]:
        calls.append("apply_opt_outs")
        return {}

    def fake_logging() -> None:
        calls.append("configure_logging")

    def fake_run(command: object, argv: object) -> int:
        calls.append("run")
        return 0

    monkeypatch.setattr(cli_app, "apply_opt_outs", fake_apply)
    monkeypatch.setattr(cli_app, "configure_logging", fake_logging)
    monkeypatch.setattr(cli_app, "run", fake_run)
    assert cli_app.main(["--help"]) == 0
    assert calls == ["apply_opt_outs", "configure_logging", "run"]
