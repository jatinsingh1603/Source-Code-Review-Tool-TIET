"""``codekavach plugins list`` and ``plugins check`` (E05-26) over real fake distributions."""

import dataclasses
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli import doctor
from codekavach.cli.errors import BackendUnavailableError
from codekavach.cli.plugins import PipelineCheck, check_registry
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.registry import PluginRegistry
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.golden import assert_matches_golden
from tests.support.pipeline import write_fake_distribution

Cli = Callable[..., CliResult]
REGISTRY = "codekavach.core.plugins.registry.registry_from_environment"
GOLDEN = Path(__file__).parent / "golden" / "plugins_check.txt"
MARKER = "SECRET-MARKER-4711"  # text inside a plugin's exception: untrusted, never printed


def stage_source(*stages: tuple[str, list[str], list[str]]) -> str:
    """A module with one stage class per ``(name, requires, provides)``."""
    lines = []
    for index, (name, requires, provides) in enumerate(stages):
        lines += [
            f"class Stage{index}:",
            f"    name = {name!r}",
            f"    requires = frozenset({requires!r})",
            f"    provides = frozenset({provides!r})",
            "    def run(self, ctx):",
            "        pass",
            "",
        ]
    return "\n".join(lines)


def install(
    site: Path,
    dist: str,
    stages: tuple[tuple[str, list[str], list[str]], ...],
    version: str = "1.0",
) -> None:
    module = dist.replace("-", "_")
    entries = {name: f"{module}:Stage{index}" for index, (name, *_rest) in enumerate(stages)}
    write_fake_distribution(
        site,
        dist,
        version,
        entry_points={"codekavach.stages": entries},
        modules={f"{module}.py": stage_source(*stages)},
    )


def serve(monkeypatch: pytest.MonkeyPatch, *dists: str) -> PluginRegistry:
    """Make the CLI build its registry from the given fake distributions only."""
    registry = PluginRegistry([spec for spec in discover() if spec.dist_name in dists])
    fake_backend(monkeypatch, REGISTRY, lambda *_settings: registry)
    return registry


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def run(cli: Cli, project: Path, *args: str) -> CliResult:
    return cli(["plugins", *args], cwd=project)


# --- list --------------------------------------------------------------------------------


def test_bare_group_behaves_as_list(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]),))
    serve(monkeypatch, "ck-one")
    bare, listed = run(cli, project), run(cli, project, "list")
    assert bare.exit_code == listed.exit_code == 0
    assert bare.stdout == listed.stdout
    header, line = bare.stdout.splitlines()[:2]
    assert header.split() == ["kind", "name", "dist", "version", "status", "error"]
    assert line.split() == ["stage", "stage-a", "ck-one", "1.0", "ok", "-"]


def test_the_table_aligns_every_row(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]), ("a-much-longer-name", ["x"], ["y"])))
    serve(monkeypatch, "ck-one")
    lines = run(cli, project, "list").stdout.splitlines()
    assert len({line.index("ck-one") for line in lines[1:]}) == 1


def test_list_json_is_one_envelope_with_the_registry_rows(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]),))
    registry = serve(monkeypatch, "ck-one")
    result = cli(["plugins", "list", "--json"], cwd=project)
    assert result.exit_code == 0
    envelope = result.json
    assert envelope["ok"] is True and envelope["command"] == "plugins list"
    assert envelope["data"]["plugins"] == [dataclasses.asdict(row) for row in registry.rows()]


def test_a_disabled_and_a_shadowed_plugin_are_listed_with_their_status(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-aaa", (("stage-a", [], ["x"]),))
    install(fake_site, "ck-zzz", (("stage-a", [], ["x"]),))
    specs = [spec for spec in discover() if spec.dist_name in {"ck-aaa", "ck-zzz"}]
    registry = PluginRegistry(specs[:1], disabled=specs[1:])
    fake_backend(monkeypatch, REGISTRY, lambda *_settings: registry)
    statuses = {
        (row["dist"], row["status"])
        for row in run(cli, project, "list", "--json").json["data"]["plugins"]
    }
    assert statuses == {("ck-aaa", "ok"), ("ck-zzz", "disabled")}


def test_an_empty_registry_says_so(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend(monkeypatch, REGISTRY, lambda *_settings: PluginRegistry([]))
    result = run(cli, project, "list")
    assert result.exit_code == 0
    assert result.stdout.strip() == "no plugin is installed"
    assert run(cli, project, "list", "--json").json["data"] == {"plugins": []}


def test_a_build_without_the_registry_exits_two(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> Any:
        raise BackendUnavailableError("the plugin registry is not available in this build")

    monkeypatch.setattr("codekavach.cli.plugins.load_backend", unavailable)
    for command in ("list", "check"):
        result = run(cli, project, command)
        assert result.exit_code == 2
        assert "error[backend_unavailable]" in result.stderr


def test_the_registry_is_built_from_the_effective_settings(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    received: list[Any] = []

    def factory(*args: Any) -> PluginRegistry:
        received.extend(args)
        return PluginRegistry([])

    fake_backend(monkeypatch, REGISTRY, factory)
    run(cli, project, "check")
    assert len(received) == 1
    assert received[0].plugins.allow_distributions == []  # the loaded Settings


# --- check -------------------------------------------------------------------------------


def test_a_resolvable_pair_prints_the_order_and_exits_zero(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]), ("stage-b", ["x"], ["y"])))
    serve(monkeypatch, "ck-one")
    result = run(cli, project, "check")
    assert result.exit_code == 0, result.stderr
    assert "order: stage-a > stage-b" in result.stdout
    assert "load errors: none" in result.stdout
    assert "unsatisfied: none" in result.stdout


def test_an_unmet_requirement_names_the_stage_and_the_key(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-b", ["x"], ["y"]),))
    serve(monkeypatch, "ck-one")
    result = run(cli, project, "check")
    assert result.exit_code == 1
    assert "stage stage-b requires x" in result.stdout
    assert "order: none" in result.stdout
    data = run(cli, project, "check", "--json").json["data"]
    assert data["unsatisfied"] == [{"stage": "stage-b", "key": "x"}]
    assert data["order"] == [] and data["cycle"] is None


def test_a_cycle_is_listed(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", ["y"], ["x"]), ("stage-b", ["x"], ["y"])))
    serve(monkeypatch, "ck-one")
    result = run(cli, project, "check")
    assert result.exit_code == 1
    cycle_line = next(line for line in result.stdout.splitlines() if line.startswith("cycle:"))
    assert {"stage-a", "stage-b"} <= set(cycle_line.removeprefix("cycle:").split(" > ")) | set()
    data = run(cli, project, "check", "--json").json["data"]
    assert sorted(data["cycle"]) == ["stage-a", "stage-b"]
    assert data["unsatisfied"] == []


def test_two_providers_of_one_key_are_reported(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]), ("stage-b", [], ["x"])))
    serve(monkeypatch, "ck-one")
    result = run(cli, project, "check")
    assert result.exit_code == 1
    assert "x is provided by stage-a, stage-b" in result.stdout


def test_a_name_collision_fails_only_with_strict(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-aaa", (("stage-a", [], ["x"]),))
    install(fake_site, "ck-zzz", (("stage-a", [], ["x"]),))
    serve(monkeypatch, "ck-aaa", "ck-zzz")
    plain = run(cli, project, "check")
    assert plain.exit_code == 0, plain.stdout
    assert "collisions: 1" in plain.stdout
    assert "codekavach.stages / stage-a (ck-zzz 1.0) lost a name collision" in plain.stdout
    strict = run(cli, project, "check", "--strict")
    assert strict.exit_code == 1
    data = run(cli, project, "check", "--json").json["data"]
    assert data["collisions"] == [
        {"group": "codekavach.stages", "name": "stage-a", "dist": "ck-zzz", "version": "1.0"}
    ]


def install_broken(site: Path, error: str = "ImportError") -> None:
    write_fake_distribution(
        site,
        "ck-broken",
        "0.3.1",
        entry_points={"codekavach.engines": {"semgrep-bridge": "ck_broken:Engine"}},
        modules={"ck_broken.py": f"raise {error}({MARKER!r})\n"},
    )


@pytest.mark.parametrize("flags", [(), ("--debug",), ("--verbose", "--verbose")])
def test_a_load_error_shows_coordinates_and_class_not_the_message(
    flags: tuple[str, ...],
    cli: Cli,
    project: Path,
    fake_site: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_broken(fake_site)
    install(fake_site, "ck-one", (("stage-a", [], ["x"]),))
    serve(monkeypatch, "ck-broken", "ck-one")
    result = cli([*flags, "plugins", "check"], cwd=project)
    assert result.exit_code == 1
    assert "load errors: 1" in result.stdout
    assert "codekavach.engines / semgrep-bridge (ck-broken 0.3.1): ImportError" in result.stdout
    assert MARKER not in result.stdout + result.stderr
    assert "order: stage-a" in result.stdout  # the rest of the plugins still resolve
    listed = cli([*flags, "plugins", "list"], cwd=project)
    assert MARKER not in listed.stdout + listed.stderr


def test_the_marker_is_absent_from_the_json_too(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_broken(fake_site, error="RuntimeError")
    serve(monkeypatch, "ck-broken")
    result = cli(["--debug", "plugins", "check", "--json"], cwd=project)
    assert MARKER not in result.stdout + result.stderr
    errors = result.json["data"]["load_errors"]
    assert errors == [
        {
            "group": "codekavach.engines",
            "name": "semgrep-bridge",
            "dist": "ck-broken",
            "version": "0.3.1",
            "stage": "import",
            "error_type": "RuntimeError",
        }
    ]


def test_the_human_report_matches_its_golden_file(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_broken(fake_site)
    install(fake_site, "ck-one", (("stage-a", [], ["x"]), ("stage-c", ["z"], ["w"])))
    serve(monkeypatch, "ck-broken", "ck-one")
    assert_matches_golden(run(cli, project, "check").stdout, GOLDEN)


def test_the_json_shape_of_check(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]),))
    serve(monkeypatch, "ck-one")
    envelope = run(cli, project, "check", "--json").json
    assert envelope["command"] == "plugins check" and envelope["exit_code"] == 0
    assert set(envelope["data"]) == {
        "order", "load_errors", "collisions", "unsatisfied", "duplicate_providers", "cycle",
    }  # fmt: skip
    assert envelope["data"]["order"] == ["stage-a"]


# --- discovery only on demand --------------------------------------------------------------------


def test_help_and_version_do_not_build_a_registry(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object) -> Any:
        raise AssertionError("the registry was built")

    fake_backend(monkeypatch, REGISTRY, forbidden)
    for args in (["--help"], ["--version"], ["plugins", "--help"], ["plugins", "check", "--help"]):
        assert cli(args, cwd=project).exit_code == 0, args


def test_the_root_help_lists_the_group(cli: Cli, project: Path) -> None:
    assert "plugins" in cli(["--help"], cwd=project).stdout


def test_importing_the_module_loads_no_plugin_code(fake_site: Path) -> None:
    install_broken(fake_site)
    import codekavach.cli.plugins  # noqa: F401, PLC0415

    assert "ck_broken" not in sys.modules


# --- the doctor check ---------------------------------------------------------------------------


def probe(cli: Cli, project: Path) -> dict[str, Any]:
    result = cli(["doctor", "--check", "plugins:pipeline", "--json"], cwd=project)
    (entry,) = result.json["data"]["checks"]
    assert isinstance(entry, dict)
    return entry


def test_the_doctor_check_is_registered_and_optional() -> None:
    check = next(c for c in doctor.all_checks() if c.name == "plugins:pipeline")
    assert check.category == "plugins"
    assert check.required is False


def test_the_doctor_check_passes_for_a_runnable_pipeline(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]), ("stage-b", ["x"], ["y"])))
    serve(monkeypatch, "ck-one")
    entry = probe(cli, project)
    assert entry["status"] == "pass"
    assert entry["details"] == {"order": ["stage-a", "stage-b"]}


def test_the_doctor_check_warns_and_points_at_the_command(
    cli: Cli, project: Path, fake_site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(fake_site, "ck-one", (("stage-b", ["x"], ["y"]),))
    serve(monkeypatch, "ck-one")
    entry = probe(cli, project)
    assert entry["status"] == "warn"
    assert entry["remediation"] == "run `codekavach plugins check` for the details"
    assert entry["details"]["problems"] == 1


def test_the_doctor_check_loads_nothing_when_the_configuration_is_invalid(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object) -> Any:
        raise AssertionError("the registry was built")

    fake_backend(monkeypatch, REGISTRY, forbidden)
    (project / "codekavach.toml").write_text('[privacy]\nlevel = "L9"\n', encoding="utf-8")
    entry = probe(cli, project)
    assert entry["status"] == "warn"
    assert entry["summary"] == "plugins not checked: the configuration is invalid"


# --- the pure function --------------------------------------------------------------------------


def test_check_registry_is_plain_data(fake_site: Path) -> None:
    install(fake_site, "ck-one", (("stage-a", [], ["x"]),))
    report = check_registry(PluginRegistry([s for s in discover() if s.dist_name == "ck-one"]))
    assert isinstance(report, PipelineCheck)
    assert report.order == ("stage-a",) and report.resolves
    assert not report.failed() and not report.failed(strict=True)
    assert report.to_data()["cycle"] is None


def test_failed_combines_the_three_conditions() -> None:
    clean = PipelineCheck((), (), (), (), (), None)
    assert not clean.failed()
    assert dataclasses.replace(clean, load_errors=({"x": "y"},)).failed()
    assert dataclasses.replace(clean, cycle=("a", "b")).failed()
    assert dataclasses.replace(clean, unsatisfied=({"stage": "a", "key": "x"},)).failed()
    collided = dataclasses.replace(clean, collisions=({"group": "g"},))
    assert not collided.failed() and collided.failed(strict=True)
