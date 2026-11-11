"""``codekavach rules list|show|validate|bundle|test``: work with native rule packs (E16-01).

Owning epic: E16. The commands read rule files (data) and never run anything from them. With
``engines.native.rules`` off, ``list`` reports zero rules instead of failing.
"""

import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer

from codekavach.cli._version import get_version
from codekavach.cli.context import get_context
from codekavach.cli.errors import UsageError
from codekavach.cli.output import get_output, simple_table

if TYPE_CHECKING:
    from codekavach.analysis.rules.pack import RulePack

rules_app = typer.Typer(
    help="List, show, validate, test and bundle native rule packs.", no_args_is_help=True
)


def _packs(ctx: typer.Context) -> "list[RulePack]":
    from codekavach.analysis.rules.errors import RuleLoadError  # noqa: PLC0415
    from codekavach.analysis.rules.loader import load_packs  # noqa: PLC0415

    settings = get_context(ctx).loaded.settings
    try:
        return load_packs(settings)
    except RuleLoadError as error:
        raise UsageError(str(error), code="rules_unloadable") from None


def _row(pack: "RulePack", rule: Any) -> dict[str, Any]:
    return {
        "id": rule.id,
        "pack": pack.id,
        "version": pack.version,
        "languages": list(rule.languages),
        "cwe": list(rule.metadata.cwe),
        "severity": rule.severity.value,
        "confidence": rule.confidence.value,
    }


@rules_app.command("list")
def list_command(ctx: typer.Context) -> None:
    """List every rule of the configured packs."""
    out = get_output(ctx)
    settings = get_context(ctx).loaded.settings
    if not settings.engines.native.rules:
        out.warn("native_rules_off", "engines.native.rules is false; no pack was loaded")
    rows = [_row(pack, rule) for pack in _packs(ctx) for rule in pack.rules]

    def human(console: Any) -> None:
        table = [
            (
                r["id"],
                f"{r['pack']} {r['version']}",
                ",".join(r["languages"]),
                ",".join(f"CWE-{n}" for n in r["cwe"]),
                r["severity"],
            )
            for r in rows
        ]
        console.print(simple_table(("rule", "pack", "languages", "cwe", "severity"), table))
        console.print(f"{len(rows)} rule(s)", markup=False)

    out.result({"rules": rows, "count": len(rows)}, human=human)


@rules_app.command("show")
def show_command(
    ctx: typer.Context, rule_id: Annotated[str, typer.Argument(help="Rule id.")]
) -> None:
    """Print one rule with its metadata, pack and fixture paths."""
    for pack in _packs(ctx):
        for rule in pack.rules:
            if rule.id == rule_id:
                data = {
                    "pack": pack.id,
                    "version": pack.version,
                    "checksum": pack.checksum,
                    "rule": rule.model_dump(mode="json", exclude_none=True),
                }
                get_output(ctx).result(data)
                return
    raise UsageError(f"no rule with id {rule_id}", code="rule_not_found")


def _pack_directories(path: Path) -> list[Path]:
    if (path / "pack.yaml").is_file():
        return [path]
    found: list[Path] = []
    for current, names, files in os.walk(path, followlinks=False):
        names.sort()
        if "pack.yaml" in files:
            found.append(Path(current))
            names.clear()
    return found


@rules_app.command("validate")
def validate_command(
    ctx: typer.Context,
    path: Annotated[Path | None, typer.Argument(help="A pack, or a directory of packs.")] = None,
) -> None:
    """Check packs and print each problem with its file, code and message."""
    from codekavach.analysis.rules.loader import default_rules_root, scan_pack  # noqa: PLC0415

    root = path if path is not None else default_rules_root()
    if root is None or not Path(root).is_dir():
        raise UsageError("give a pack or a directory of packs to validate", code="rules_path")
    directories = _pack_directories(Path(root))
    if not directories:
        raise UsageError(f"no pack.yaml found under {root}", code="no_packs")
    packs: list[dict[str, Any]] = []
    problems: list[dict[str, str | None]] = []
    for directory in directories:
        scan = scan_pack(directory, check_patterns=True)
        issues = [
            {
                "code": item.code.value,
                "message": item.message,
                "rule": item.rule_id,
                "path": item.path,
            }
            for item in scan.issues
        ]
        problems.extend(issues)
        packs.append(
            {
                "path": directory.as_posix(),
                "pack": scan.pack.id if scan.pack else None,
                "version": scan.pack.version if scan.pack else None,
                "rules": len(scan.pack.rules) if scan.pack else 0,
                "checksum": scan.pack.checksum if scan.pack else None,
                "issues": len(issues),
            }
        )

    def human(console: Any) -> None:
        for item in problems:
            where = item["path"] or item["rule"] or ""
            console.print(f"{where}: {item['code']} {item['message']}", markup=False)
        for row in packs:
            console.print(
                f"{row['pack'] or row['path']}: {row['rules']} rule(s), {row['issues']} problem(s)",
                markup=False,
            )

    get_output(ctx).result({"packs": packs, "problems": problems}, human=human)
    if problems:
        raise UsageError(f"{len(problems)} rule problem(s)", code="rules_invalid")


@rules_app.command("bundle")
def bundle_command(
    ctx: typer.Context,
    out: Annotated[Path, typer.Option("--out", help="Where to write the bundle (.ckrules).")],
) -> None:
    """Write a deterministic, checksummed archive of the configured packs."""
    from codekavach.analysis.rules.bundle import write_bundle  # noqa: PLC0415

    packs = _packs(ctx)
    if not packs:
        raise UsageError("no pack is configured or loadable", code="no_packs")
    digest = write_bundle(packs, out, codekavach_version=get_version())
    rows = [{"id": p.id, "version": p.version, "checksum": p.checksum} for p in packs]
    get_output(ctx).result({"file": str(out), "sha256": digest, "packs": rows})


@rules_app.command("test")
def test_command(
    ctx: typer.Context,
    pack: Annotated[str | None, typer.Option("--pack", help="Only this pack id.")] = None,
    rule: Annotated[str | None, typer.Option("--rule", help="Only this rule id.")] = None,
    fixtures: Annotated[
        Path | None,
        typer.Option("--fixtures", help="Fixture root (default: tests/fixtures/rules)."),
    ] = None,
    update: Annotated[
        bool,
        typer.Option("--update", help="Rewrite annotations from actual matches (never in CI)."),
    ] = False,
) -> None:
    """Check each rule against its annotated fixture and print what differs."""
    from codekavach.analysis.rules.loader import default_rules_root  # noqa: PLC0415
    from codekavach.analysis.rules.matcher import Matcher  # noqa: PLC0415
    from codekavach.analysis.rules.testing import (  # noqa: PLC0415
        check_rule,
        run_rule_tests,
        update_fixture,
    )

    if update and os.environ.get("CI"):
        raise UsageError("--update is refused when CI is set", code="update_in_ci")
    root = fixtures
    if root is None:
        rules_root = default_rules_root()
        root = (rules_root.parent if rules_root else Path.cwd()) / "tests" / "fixtures" / "rules"
    packs = [item for item in _packs(ctx) if pack is None or item.id == pack]
    if update:
        matcher, _ = Matcher.for_packs(packs)
        for item in packs:
            for entry in item.rules:
                if rule is not None and entry.id != rule:
                    continue
                for language in entry.languages:
                    if check_rule(matcher, entry, language, root).problem != "no fixture":
                        update_fixture(matcher, entry, language, root)
    report = run_rule_tests(packs, root, pack_id=pack, rule_id=rule)
    rows = [
        {
            "rule": item.rule_id,
            "language": item.language,
            "fixture": item.fixture,
            "passed": item.passed,
            "missing": list(item.missing),
            "unexpected": list(item.unexpected),
            "known_gaps": item.todo_open,
            "fixed_gaps": item.todo_fixed,
            "problem": item.problem,
        }
        for item in report.results
    ]

    def human(console: Any) -> None:
        for item in report.results:
            mark = "PASS" if item.passed else "FAIL"
            console.print(f"{mark} {item.rule_id} [{item.language}]", markup=False)
            for line in item.missing:
                console.print(
                    f"  {item.fixture}:{line}: expected a match, found none", markup=False
                )
            for line in item.unexpected:
                console.print(f"  {item.fixture}:{line}: unexpected match", markup=False)
            if item.problem:
                console.print(f"  {item.fixture}: {item.problem}", markup=False)
        console.print(
            f"{sum(r.passed for r in report.results)}/{len(report.results)} passed, "
            f"{report.known_gaps} known gap(s)",
            markup=False,
        )

    get_output(ctx).result(
        {"passed": report.passed, "known_gaps": report.known_gaps, "results": rows}, human=human
    )
    if not report.passed:
        raise UsageError("rule tests failed", code="rules_test_failed")
