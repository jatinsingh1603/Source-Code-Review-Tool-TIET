"""The Opengrep, Bandit and ESLint adapters without any engine installed (E15-01)."""

import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from codekavach.analysis.engines.adapters import common
from codekavach.analysis.engines.adapters.bandit import BanditAdapter, report_to_sarif
from codekavach.analysis.engines.adapters.eslint_security import (
    CONFIG_NAME,
    EslintSecurityAdapter,
    install_config,
    tools_dir,
)
from codekavach.analysis.engines.adapters.eslint_security import (
    report_to_sarif as eslint_to_sarif,
)
from codekavach.analysis.engines.adapters.opengrep import OpengrepAdapter, rule_directories
from codekavach.analysis.engines.base import EngineAdapter, EngineInvocation, EngineRun
from codekavach.analysis.engines.errors import CODE_ERROR, CODE_UNAVAILABLE
from codekavach.analysis.engines.manifest import licence_inventory, load_manifest
from codekavach.analysis.engines.registry import EngineRegistry
from codekavach.analysis.engines.runner import RunLimits, run_engine
from codekavach.analysis.engines.sarif.cwe import MAX_CWE
from codekavach.analysis.engines.sarif.errors import SarifFormatError
from codekavach.analysis.engines.sarif.tables import default_cwe_fallback
from codekavach.analysis.engines.stage import AnalyseEnginesStage
from codekavach.analysis.engines.worktree import neutralise_repo_config
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language
from codekavach.core.models.taxonomy import parse_cwe
from codekavach.core.pipeline import keys
from tests.support.engines import (
    OUTPUT_FILE,
    StubSandbox,
    make_engine_context,
    source_file,
    stub_sandboxes,
)
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).parent / "golden"
QUOTED_PASSWORD_TEXT = "Possible hardcoded password: 'SYNTHETIC-VALUE'"  # pragma: allowlist secret
FILES = [source_file("app.py"), source_file("server.js", Language.JAVASCRIPT)]


def settings_for(tmp_path: Path) -> Settings:
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    return Settings.model_validate(
        {
            "engines": {
                "rule_paths": [str(rules)],
                "options": {"eslint-security": {"options": {"tools_dir": str(tmp_path / "tools")}}},
            }
        }
    )


def portable(part: str, tmp_path: Path) -> str:
    """``part`` with the temporary directory replaced and separators made ``/``."""
    return (
        part.replace(str(tmp_path), "<tmp>")
        .replace(tmp_path.as_posix(), "<tmp>")
        .replace(chr(92), "/")
    )


def snapshot(invocation: EngineInvocation | None, tmp_path: Path) -> str:
    assert invocation is not None
    text = json.dumps(
        {
            "argv": [portable(part, tmp_path) for part in invocation.argv],
            "workdir": invocation.workdir,
            "output_file": invocation.output_file,
            "expect_exit_codes": sorted(invocation.expect_exit_codes),
        },
        indent=2,
    )
    return text + chr(10)


ADAPTERS: dict[str, type[EngineAdapter]] = {
    "opengrep": OpengrepAdapter,
    "bandit": BanditAdapter,
    "eslint-security": EslintSecurityAdapter,
}


@pytest.mark.parametrize("engine", sorted(ADAPTERS))
def test_the_argument_vector_matches_its_snapshot(engine: str, tmp_path: Path) -> None:
    adapter = ADAPTERS[engine]()
    found = adapter.build_invocation(tmp_path, FILES, settings_for(tmp_path))
    assert_matches_golden(snapshot(found, tmp_path), GOLDEN / f"{engine}.invocation.json")


def test_opengrep_reads_rules_only_from_directories_and_never_from_a_registry(
    tmp_path: Path,
) -> None:
    found = OpengrepAdapter().build_invocation(tmp_path, FILES, settings_for(tmp_path))
    assert found is not None
    argv = found.argv
    configs = [argv[i + 1] for i, part in enumerate(argv) if part == "--config"]
    assert configs == [str(tmp_path / "rules")]
    for part in argv:
        assert not part.startswith(("p/", "r/", "http", "auto"))
        assert part not in {"auto", "--metrics", "--disable-version-check"}
    assert "--taint-intrafile" in argv
    assert "--no-rewrite-rule-ids" in argv


def test_opengrep_without_a_rule_directory_has_nothing_to_run(tmp_path: Path) -> None:
    assert OpengrepAdapter().build_invocation(tmp_path, FILES, Settings()) is None
    missing = Settings.model_validate({"engines": {"rule_paths": [str(tmp_path / "nowhere")]}})
    assert rule_directories(missing) == []


def test_the_manifest_rows_record_licence_and_the_telemetry_decision() -> None:
    rows = load_manifest()
    assert rows["opengrep"].no_documented_opt_out and rows["bandit"].no_documented_opt_out
    assert rows["eslint-security"].telemetry_env == {"DO_NOT_TRACK": "1"}
    inventory = {
        row.engine: row for row in licence_inventory([a().spec for a in ADAPTERS.values()])
    }
    assert {k: v.spdx_licence for k, v in inventory.items()} == {
        "opengrep": "LGPL-2.1",
        "bandit": "Apache-2.0",
        "eslint-security": "MIT",
    }
    assert all(row.version for row in inventory.values())


def test_the_three_adapters_are_found_through_the_entry_point_group() -> None:
    registry = EngineRegistry()
    added = registry.load_plugins(Settings())
    assert {"opengrep", "bandit", "eslint-security"} <= set(added)


# --- exit codes ---


@pytest.mark.parametrize(
    ("engine", "code", "status"),
    [
        ("opengrep", 0, "ok"),
        ("opengrep", 1, "ok"),
        ("opengrep", 2, "error"),
        ("bandit", 0, "ok"),
        ("bandit", 1, "error"),
        ("eslint-security", 0, "ok"),
        ("eslint-security", 1, "ok"),
        ("eslint-security", 2, "error"),
    ],
)
def test_exit_codes_mean_findings_or_failure(
    engine: str, code: int, status: str, tmp_path: Path
) -> None:
    adapter = ADAPTERS[engine]()
    found = adapter.build_invocation(tmp_path, FILES, settings_for(tmp_path))
    assert found is not None
    found = dataclasses.replace(found, output_file=OUTPUT_FILE)
    limits = RunLimits(timeout_seconds=5.0, root=tmp_path, out_dir=tmp_path / "out")
    run = run_engine(adapter, found, sandbox=StubSandbox(exit_code=code), limits=limits)
    assert run.status == status
    assert (run.error_code == CODE_ERROR) == (status == "error")


# --- repository configuration is hidden ---


@pytest.mark.parametrize(
    ("engine", "names"),
    [
        (
            "eslint-security",
            [
                "eslint.config.js",
                "eslint.config.mjs",
                ".eslintrc.json",
                ".eslintrc",
                "a/.eslintrc.cjs",
            ],
        ),
        ("opengrep", [".semgrepignore", ".opengrepignore", ".semgrep.yml"]),
        ("bandit", [".bandit", "bandit.yaml"]),
    ],
)
def test_the_repository_configuration_is_hidden_from_the_engine(
    engine: str, names: list[str], tmp_path: Path
) -> None:
    view = tmp_path / "view"
    for name in [*names, "keep.py"]:
        target = view / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x", encoding="utf-8")
    hidden = neutralise_repo_config(view, ADAPTERS[engine]().spec)
    assert sorted(hidden) == sorted(names)
    assert [p.name for p in view.rglob("*") if p.is_file()] == ["keep.py"]


def test_the_eslint_invocation_cannot_load_the_repository_configuration(tmp_path: Path) -> None:
    found = EslintSecurityAdapter().build_invocation(tmp_path, FILES, settings_for(tmp_path))
    assert found is not None
    argv = found.argv
    assert "--no-config-lookup" in argv and "--no-inline-config" in argv
    config = argv[argv.index("-c") + 1]
    assert Path(config) == tmp_path / "tools" / CONFIG_NAME


# --- probes ---


def settings_with_executable(engine: str, executable: str, **extra: Any) -> Settings:
    return Settings.model_validate(
        {"engines": {"options": {engine: {"executable": executable, **extra}}}}
    )


@pytest.mark.parametrize("engine", sorted(ADAPTERS))
def test_a_missing_executable_is_unavailable_with_an_install_hint(
    engine: str, tmp_path: Path
) -> None:
    adapter = ADAPTERS[engine]()
    gone = settings_with_executable(engine, str(tmp_path / "no-such-tool"))
    probe = adapter.probe(gone)
    assert probe.available is False and probe.reason
    assert adapter.install_hint()


def test_eslint_needs_its_plugins_in_the_tools_directory(tmp_path: Path) -> None:
    here = settings_with_executable(
        "eslint-security", sys.executable, options={"tools_dir": str(tmp_path / "t")}
    )
    probe = EslintSecurityAdapter().probe(here)
    assert probe.available is False
    assert probe.reason is not None and "eslint" in probe.reason
    for package, version in (
        ("eslint", "10.14.0"),
        ("eslint-plugin-security", "4.2.1"),
        ("eslint-plugin-no-unsanitized", "4.1.5"),
    ):
        folder = tmp_path / "t" / "node_modules" / package
        folder.mkdir(parents=True)
        (folder / "package.json").write_text(json.dumps({"version": version}), encoding="utf-8")
    found = EslintSecurityAdapter().probe(here)
    assert (found.available, found.version) == (True, "10.14.0")


def test_the_client_node_modules_are_never_the_tools_directory(tmp_path: Path) -> None:
    assert "node_modules" not in tools_dir(Settings()).parts
    assert tools_dir(settings_for(tmp_path)) == tmp_path / "tools"


def test_probe_version_reads_the_version_from_the_engine() -> None:
    probe = common.probe_version("t", sys.executable, ("-c", "print('tool 12.3.4 (build)')"))
    assert (probe.available, probe.version) == (True, "12.3.4")
    failing = common.probe_version("t", sys.executable, ("-c", "raise SystemExit(3)"))
    assert failing.available is False
    silent = common.probe_version("t", sys.executable, ("-c", "print('no digits')"))
    assert silent.available is False


# --- ESLint and Bandit reports ---


def test_install_config_copies_once_and_repairs_a_changed_copy(tmp_path: Path) -> None:
    target = install_config(tmp_path / "tools")
    assert target.read_bytes().startswith(b"// The only ESLint configuration")
    target.write_text("export default [];", encoding="utf-8")
    assert install_config(tmp_path / "tools").read_bytes().startswith(b"// The only ESLint")


def test_eslint_parse_errors_and_source_text_are_not_carried() -> None:
    report = [
        {
            "filePath": "/src/a.js",
            "source": "SOURCE-TEXT-MARK",
            "messages": [
                {
                    "ruleId": None,
                    "fatal": True,
                    "severity": 2,
                    "message": "Parsing error",
                    "line": 1,
                    "column": 1,
                },
                {
                    "ruleId": "security/detect-eval-with-expression",
                    "severity": 1,
                    "message": "m",
                    "line": 2,
                    "column": 1,
                },
            ],
        }
    ]
    data, fatal = eslint_to_sarif(report)
    assert fatal == 1
    assert b"SOURCE-TEXT-MARK" not in data
    assert (
        json.loads(data)["runs"][0]["results"][0]["ruleId"]
        == "security/detect-eval-with-expression"
    )


@pytest.mark.parametrize("report", [{}, [{"messages": "x"}], "text", None])
def test_a_malformed_eslint_report_raises(report: object) -> None:
    with pytest.raises(SarifFormatError):
        eslint_to_sarif(report)


@pytest.mark.parametrize(
    "report",
    [{}, {"results": "x"}, {"results": [{"filename": "a.py"}]}, {"results": [{"test_id": "B1"}]}],
)
def test_a_malformed_bandit_report_raises(report: object) -> None:
    with pytest.raises(SarifFormatError):
        report_to_sarif(report)


def test_bandit_password_text_is_replaced_before_it_reaches_a_candidate() -> None:
    report = {
        "results": [
            {
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "filename": "a.py",
                "line_number": 1,
                "line_range": [1],
                "issue_severity": "LOW",
                "issue_confidence": "MEDIUM",
                "issue_text": QUOTED_PASSWORD_TEXT,
            }
        ]
    }
    run = json.loads(report_to_sarif(report))["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["properties"] == {"tags": ["secret"]}


def test_the_bandit_invocation_ignores_nosec_and_exits_zero(tmp_path: Path) -> None:
    found = BanditAdapter().build_invocation(tmp_path, FILES, Settings())
    assert found is not None
    assert {"--exit-zero", "--ignore-nosec"} <= set(found.argv)
    assert (
        BanditAdapter().build_invocation(
            tmp_path, [source_file("a.js", Language.JAVASCRIPT)], Settings()
        )
        is None
    )


def test_eslint_with_too_many_files_lints_a_capped_sorted_list(tmp_path: Path) -> None:
    many = [source_file(f"f{n:02d}.js", Language.JAVASCRIPT) for n in (3, 1, 2)]
    capped = Settings.model_validate(
        {
            "engines": {
                "options": {
                    "eslint-security": {"options": {"tools_dir": str(tmp_path), "max_files": 2}}
                }
            }
        }
    )
    found = EslintSecurityAdapter().build_invocation(tmp_path, many, capped)
    assert found is not None
    assert found.argv[-2:] == ("f01.js", "f02.js")


# --- the CWE table ---


def test_the_shipped_cwe_rows_are_valid_and_parse() -> None:
    rows = default_cwe_fallback().engines["eslint-security"]
    assert rows
    for numbers in rows.values():
        for number in numbers:
            assert 1 <= parse_cwe(number) <= MAX_CWE


# --- degrade ---


def test_two_unavailable_adapters_degrade_the_stage_and_do_not_fail_the_scan(
    tmp_path: Path,
) -> None:
    registry = EngineRegistry()
    registry.register(BanditAdapter())
    registry.register(EslintSecurityAdapter())
    ctx = make_engine_context(
        tmp_path,
        files=FILES,
        engines={
            "enabled": ["bandit", "eslint-security"],
            "options": {
                "bandit": {"executable": str(tmp_path / "no-bandit")},
                "eslint-security": {"executable": str(tmp_path / "no-node")},
            },
        },
    )
    stage = AnalyseEnginesStage(
        registry, sandboxes=lambda _s: stub_sandboxes(StubSandbox()), discover_plugins=False
    )
    stage.run(ctx)
    failed = {(f.item_id, f.error_code) for f in ctx.item_failures.snapshot()}
    assert failed == {("bandit", CODE_UNAVAILABLE), ("eslint-security", CODE_UNAVAILABLE)}
    parts = ctx.artefacts.get_parts(keys.CANDIDATES_RAW, Candidate)
    assert parts.get("analyse-engines", []) == []


def test_run_dataclass_is_what_parse_receives(tmp_path: Path) -> None:
    run = EngineRun("bandit", "1.9.4", 0, 0.0, "ok")
    with pytest.raises(SarifFormatError):
        BanditAdapter().parse(run, tmp_path)


def test_the_rule_and_tool_directories_are_declared_for_a_container_mount(
    tmp_path: Path,
) -> None:
    settings = settings_for(tmp_path)
    opengrep = OpengrepAdapter().build_invocation(tmp_path, FILES, settings)
    eslint = EslintSecurityAdapter().build_invocation(tmp_path, FILES, settings)
    assert opengrep is not None and eslint is not None
    assert opengrep.read_only_paths == (str(tmp_path / "rules"),)
    assert eslint.read_only_paths == (str(tmp_path / "tools"),)
    assert BanditAdapter().build_invocation(tmp_path, FILES, settings) is not None
