"""``codekavach providers``: which LLM providers are configured, and how each would be used.

Owning epic: E05.

``providers list`` answers, from configuration and the adapter registry only, which providers
exist, which one would be used, whether each is local or remote, which privacy floor applies to
it and whether its credential is available. It contacts nothing and, by default, does not touch
the keyring, so it is safe to run in an untrusted repository. ``--check-secrets`` asks
``secret_status``, which reports availability and never returns a value.

Output names secret references (``env:NAME``) and their state, never key material, and shows the
host of a ``base_url``, not the URL. Adapters and the resolution of ``auto`` belong to E22 and are
reached through ``load_backend``; until E22 lands an adapter is reported as ``missing`` and
``auto`` is shown as ``mock`` with the warning ``auto_resolution_unavailable``.
"""

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Annotated, Any, Final

import typer
from rich.console import Console

from codekavach.cli.backends import load_backend
from codekavach.cli.context import CliContext, get_context
from codekavach.cli.errors import BackendUnavailableError
from codekavach.cli.output import Output, get_output
from codekavach.config import keys

if TYPE_CHECKING:
    from codekavach.config.models.llm import ProviderSettings

AUTO: Final = "auto"
FALLBACK_PROVIDER: Final = "mock"
BLOCKED: Final = "blocked (remote not allowed)"
CAPABILITY_FIELDS: Final = ("structured_output", "tool_calling", "context_window", "batch", "local")
DISABLED_LINE: Final = "LLM review is disabled (llm.enabled = false)"

providers_app = typer.Typer(help="Inspect and test LLM providers.", no_args_is_help=True)


def adapters() -> Mapping[str, object]:
    """The provider adapters of this build, by kind; empty when the registry cannot be read."""
    try:
        registry = load_backend(
            "codekavach.core.plugins.registry",
            "registry_from_environment",
            feature="the plugin registry",
            epic="E04",
        )()
    except BackendUnavailableError:
        return {}
    found: Mapping[str, object] = registry.providers()
    return found


def capabilities(adapter: object | None) -> dict[str, Any] | None:
    """The capabilities of an adapter as plain data; ``None`` when the adapter is missing."""
    if adapter is None:
        return None
    source = getattr(adapter, "capabilities", None)
    result: dict[str, Any] = {}
    for name in CAPABILITY_FIELDS:
        value = getattr(source, name, None)
        if name == "context_window":
            result[name] = value if isinstance(value, int) and not isinstance(value, bool) else None
        else:
            result[name] = bool(value)
    return result


def credential_state(
    provider: "ProviderSettings", cli_ctx: CliContext, *, check: bool
) -> tuple[str, list[str]]:
    """``(state, references)``: the state is ``unchecked`` unless ``check`` is set."""
    refs = list(keys.effective_key_refs(str(provider.kind), provider.api_key))
    if not refs:
        return "not-required", refs
    if not check:
        return "unchecked", refs
    root = cli_ctx.loaded.project_root
    states = [keys.secret_status(ref, project_root=root).state for ref in refs]
    if "set" in states:
        return "set", refs
    return ("backend-unavailable" if "backend-unavailable" in states else "not-set"), refs


def default_provider(cli_ctx: CliContext, out: Output) -> str | None:
    """The provider a scan would use; ``None`` when the LLM is disabled."""
    llm = cli_ctx.settings.llm
    if not llm.enabled:
        return None
    if llm.default_provider != AUTO:
        return llm.default_provider
    try:
        resolve = load_backend(
            "codekavach.llm.selection",
            "resolve_default_provider",
            feature="automatic provider selection",
            epic="E22",
        )
    except BackendUnavailableError:
        out.warn(
            "auto_resolution_unavailable",
            "llm.default_provider is auto and provider selection is not in this build; "
            f"{FALLBACK_PROVIDER} is used",
        )
        return FALLBACK_PROVIDER
    return str(resolve(cli_ctx.settings))


def provider_rows(
    cli_ctx: CliContext, *, default: str | None, check_secrets: bool, include_disabled: bool
) -> list[dict[str, Any]]:
    """One JSON-ready row per configured provider."""
    settings = cli_ctx.settings
    installed = adapters()
    rows: list[dict[str, Any]] = []
    for provider_id, provider in settings.llm.providers.items():
        if not provider.enabled and not include_disabled:
            continue
        kind = str(provider.kind)
        tier = provider.effective_trust_tier
        state, refs = credential_state(provider, cli_ctx, check=check_secrets)
        adapter = installed.get(kind)
        rows.append(
            {
                "id": provider_id,
                "kind": kind,
                "model": provider.model or settings.llm.model,
                "enabled": provider.enabled,
                "blocked": provider.is_remote and not settings.llm.allow_remote,
                "locality": "remote" if provider.is_remote else "local",
                "host": provider.host,
                "trust_tier": tier.value,
                "min_level": settings.privacy.floor_for_tier(tier).value,
                "credential": state,
                "credential_refs": refs,
                "adapter": "available" if adapter is not None else "missing",
                "capabilities": capabilities(adapter),
                "default": provider_id == default,
            }
        )
    return rows


def _enabled_text(row: Mapping[str, Any]) -> str:
    if row["blocked"]:
        return BLOCKED
    return "yes" if row["enabled"] else "no"


def text_table(columns: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    """Aligned plain-text lines: a header and one line per row, never folded."""
    widths = [len(column) for column in columns]
    for row in rows:
        widths = [max(width, len(cell)) for width, cell in zip(widths, row, strict=True)]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        for line in (columns, *rows)
    ]


def _print(console: Console, lines: Sequence[str]) -> None:
    for line in lines:
        console.print(line, markup=False, highlight=False, soft_wrap=True)


def _render_list(
    rows: list[dict[str, Any]], *, default: str | None, configured: str, llm_enabled: bool
) -> Any:
    def render(console: Console) -> None:
        if not llm_enabled:
            console.print(DISABLED_LINE, markup=False)
        columns = (
            " ", "id", "kind", "model", "enabled", "locality", "host", "tier", "min level",
            "credential", "adapter",
        )  # fmt: skip
        table = [
            (
                "*" if row["default"] else " ",
                row["id"],
                row["kind"],
                row["model"] or "-",
                _enabled_text(row),
                row["locality"],
                row["host"] or "-",
                row["trust_tier"],
                row["min_level"],
                row["credential"],
                row["adapter"],
            )
            for row in rows
        ]
        _print(console, text_table(columns, table))
        if default is not None:
            console.print(
                f'default: {default} (llm.default_provider = "{configured}")', markup=False
            )

    return render


def _render_kinds(kinds: list[dict[str, Any]]) -> Any:
    def render(console: Console) -> None:
        if not kinds:
            console.print("no provider adapter is installed in this build", markup=False)
            return
        table = [
            (
                item["kind"],
                *(
                    "-" if item["capabilities"][name] is None else str(item["capabilities"][name])
                    for name in CAPABILITY_FIELDS
                ),
            )
            for item in kinds
        ]
        _print(console, text_table(("kind", *CAPABILITY_FIELDS), table))

    return render


@providers_app.command("list")
def list_command(
    ctx: typer.Context,
    kinds: Annotated[
        bool, typer.Option("--kinds", help="List the adapter kinds of this build instead.")
    ] = False,
    check_secrets: Annotated[
        bool,
        typer.Option("--check-secrets", help="Report whether each credential reference resolves."),
    ] = False,
    include_disabled: Annotated[
        bool, typer.Option("--all", help="Include disabled providers.")
    ] = False,
) -> None:
    """List the configured providers; contacts nothing."""
    out = get_output(ctx)
    if kinds:
        installed = adapters()
        found = [
            {"kind": kind, "capabilities": capabilities(installed[kind])}
            for kind in sorted(installed)
        ]
        out.result({"kinds": found}, human=_render_kinds(found))
        return
    cli_ctx = get_context(ctx)
    llm = cli_ctx.settings.llm
    default = default_provider(cli_ctx, out)
    rows = provider_rows(
        cli_ctx, default=default, check_secrets=check_secrets, include_disabled=include_disabled
    )
    out.result(
        {
            "default": default,
            "llm_enabled": llm.enabled,
            "allow_remote": llm.allow_remote,
            "providers": rows,
        },
        human=_render_list(
            rows, default=default, configured=llm.default_provider, llm_enabled=llm.enabled
        ),
    )
