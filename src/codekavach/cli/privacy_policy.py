"""``codekavach privacy explain`` and ``codekavach privacy score`` (E25-03, E28-03).

``explain`` shows why a file, or a candidate of a stored scan, is prepared at a given level: every
contribution of every policy axis with its source, and which one won. Patterns appear here (this is
the operator's terminal) and nowhere outside it. ``score`` prints the attestation score with each
component labelled measured, indicative or not computed.
"""

from pathlib import Path
from typing import Annotated, Any

import typer

from codekavach.cli.context import get_context, with_target
from codekavach.cli.errors import UsageError
from codekavach.cli.output import get_output

NOT_COMPUTED = "not computed"


def _decision_json(path: str, decision: Any) -> dict[str, Any]:
    return {
        "path": path,
        "level": decision.level.value,
        "never_send": decision.never_send,
        "classifications": list(decision.classifications),
        "rule_key": decision.rule_key,
        "policy_hash": decision.policy_hash,
        "contributions": [
            {
                "axis": c.axis,
                "key": c.key,
                "level": c.level.value if c.level else "never_send",
                "source": c.detail,
                "winner": c is decision.winner,
            }
            for c in decision.contributions
        ],
    }


def explain_command(
    ctx: typer.Context,
    subject: Annotated[str, typer.Argument(help="A project file path or a candidate id.")],
    target: Annotated[Path, typer.Option("--project", help="Project directory.")] = Path(),
    scan: Annotated[str, typer.Option("--scan", help="Scan id, or latest.")] = "latest",
) -> None:
    """Explain the effective privacy level of a file or candidate, axis by axis."""
    from codekavach.cli.privacy import resolve_scan  # noqa: PLC0415
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415
    from codekavach.core.models.candidate import Candidate  # noqa: PLC0415
    from codekavach.core.pipeline import keys  # noqa: PLC0415
    from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415
    from codekavach.ingest.langdetect import detect_language  # noqa: PLC0415
    from codekavach.privacy.policy.engine import PolicyEngine  # noqa: PLC0415

    if not target.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    cli_ctx = with_target(ctx, target)
    loaded = get_context(ctx).loaded
    settings = cli_ctx.settings
    engine = PolicyEngine.discover(settings, loaded.project_root)
    _, provider = settings.llm.selected_provider()
    tier = provider.effective_trust_tier
    language: str | None = None
    rule_id: str | None = None
    cwes: tuple[str, ...] = ()
    path = subject
    if subject.startswith(("cand_", "find_")):
        state = StateLayout(
            resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir)
        )
        store = OnDiskArtefactStore.open_existing(state, resolve_scan(state, scan))
        found = [c for c in store.get_list(keys.CANDIDATES, Candidate) if str(c.id) == subject]
        if not found:
            raise UsageError(f"no candidate {subject} in the scan", code="candidate_not_found")
        cand = found[0]
        path = cand.locations[0].path
        language, rule_id, cwes = cand.language.value, cand.rule_id, tuple(str(c) for c in cand.cwe)
    else:
        file = loaded.project_root / subject
        head = file.read_bytes()[:4096] if file.is_file() else b""
        language = detect_language(subject, head).value
    decision = engine.resolve(path, tier, language=language, rule_id=rule_id, cwes=cwes)
    data = _decision_json(path, decision)

    def human(console: Any) -> None:
        verdict = "NEVER SENT" if decision.never_send else decision.level.value
        console.print(f"{path}: effective level {verdict} (provider tier {tier.value})")
        console.print(f"decided by {decision.winner.axis}: {decision.winner.detail or '-'}")
        for item in decision.contributions:
            mark = "*" if item is decision.winner else " "
            level = item.level.value if item.level else "never_send"
            console.print(f" {mark} {item.axis:<14} {level:<10} {item.detail}", markup=False)
        if decision.classifications:
            console.print("classifications: " + ", ".join(decision.classifications), markup=False)
        console.print(
            f"policy hash {decision.policy_hash[:16]}  rule key {decision.rule_key}", markup=False
        )

    get_output(ctx).result(data, human=human)


def score_command(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Project directory.")] = Path(),
    scan: Annotated[str, typer.Option("--scan", help="Scan id, or latest.")] = "latest",
) -> None:
    """Show the privacy score of a stored scan with every component and its kind."""
    from codekavach.cli.privacy import resolve_scan  # noqa: PLC0415
    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415
    from codekavach.privacy.attestation import build_attestation  # noqa: PLC0415

    if not target.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    cli_ctx = with_target(ctx, target)
    loaded = get_context(ctx).loaded
    state = StateLayout(resolve_state_dir(loaded.project_root, loaded.settings.project.state_dir))
    scan_id = resolve_scan(state, scan)
    attestation = build_attestation(state, scan_id, cli_ctx.settings)
    data = attestation.to_api()

    def human(console: Any) -> None:
        score = attestation.score
        console.print(f"privacy score {score.score}/100 for {scan_id}", markup=False)
        for comp in score.components:
            value = NOT_COMPUTED if comp.value is None else f"{comp.value:g}"
            console.print(f"  {comp.name:<18} {value:>12}  [{comp.kind}]  {comp.raw}", markup=False)
        for cap in score.caps:
            console.print(f"  cap: {cap}", markup=False)
        console.print(score.formula, markup=False)

    get_output(ctx).result(data, human=human)
