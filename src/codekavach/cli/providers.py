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

``providers test`` asks whether a provider answers a constant probe. It causes an outbound LLM
request, so it follows the rules of a scan (I1, I2, I4): the pre-flight refuses an unknown,
disabled or adapter-less provider, a remote provider when remote use is not allowed, and a run
without consent, each before anything is sent. The probe itself belongs to E22 and is sent by the
egress transport only. This module passes identifiers and settings: it builds no request, reads no
project file and opens no connection. A provider's raw error body is never printed, because some
providers echo request headers or parts of the key; only a reason code and its hint are shown.
"""

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Annotated, Any, Final

import typer
from rich.console import Console

from codekavach.cli.backends import load_backend
from codekavach.cli.consent import EgressConsent, ensure_egress_consent
from codekavach.cli.context import CliContext, get_context
from codekavach.cli.errors import (
    BackendUnavailableError,
    PrivacyBlockError,
    ThresholdExceeded,
    UsageError,
)
from codekavach.cli.onboarding import maybe_show_first_run_notice
from codekavach.cli.output import Output, get_output
from codekavach.config import keys

if TYPE_CHECKING:
    from codekavach.config.models.llm import ProviderSettings

AUTO: Final = "auto"
FALLBACK_PROVIDER: Final = "mock"
BLOCKED: Final = "blocked (remote not allowed)"
CAPABILITY_FIELDS: Final = ("structured_output", "tool_calling", "context_window", "batch", "local")
DISABLED_LINE: Final = "LLM review is disabled (llm.enabled = false)"
DEFAULT_PROBE_TIMEOUT: Final = 30.0
LOCAL_DOUBLES: Final = frozenset({"mock", "replay"})
LOCAL_DOUBLE_LINE: Final = "local test double: no network request was made"
STRUCTURED_STATES: Final = frozenset({"passed", "failed", "not-tested"})
_NETWORK_HINT: Final = (
    "check network access and proxy settings; for local providers check that the server is running"
)
REASON_HINTS: Final[Mapping[str, str]] = {
    "unauthorised": (
        "check the secret reference with `codekavach config key status`; "
        "the key value is never shown"
    ),
    "model_not_found": (
        "the configured model name is not offered by this provider; "
        "see `codekavach providers list --kinds`"
    ),
    "unreachable": _NETWORK_HINT,
    "timeout": _NETWORK_HINT,
    "tls_error": (
        "the endpoint certificate was rejected; "
        "`allow_insecure_http` does not disable certificate checks"
    ),
    "rate_limited": "the provider throttled the probe; try again later",
    "bad_response": (
        "the provider answered in an unexpected format; run with `--debug` and report an issue"
    ),
}
FALLBACK_REASON: Final = "bad_response"

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


# providers test (E05-23)


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def probe_data(result: object, *, provider_id: str, kind: str) -> dict[str, Any]:
    """The fields of a probe result that may be shown; anything else it carries is ignored."""
    ok = getattr(result, "ok", False) is True
    structured = getattr(result, "structured_output", None)
    reason = getattr(result, "reason_code", None)
    model = getattr(result, "model", None)
    data: dict[str, Any] = {
        "ok": ok,
        "provider_id": provider_id,
        "kind": kind,
        "model": model if isinstance(model, str) else None,
        "latency_ms": _count(getattr(result, "latency_ms", None)),
        "prompt_tokens": _count(getattr(result, "prompt_tokens", None)),
        "completion_tokens": _count(getattr(result, "completion_tokens", None)),
        "structured_output": structured if structured in STRUCTURED_STATES else "not-tested",
        "ledger_seq": _count(getattr(result, "ledger_seq", None)),
        "reason_code": None,
        "hint": None,
    }
    if not ok:
        code = reason if isinstance(reason, str) and reason in REASON_HINTS else FALLBACK_REASON
        data["reason_code"] = code
        data["hint"] = REASON_HINTS[code]
    return data


def probe_lines(data: Mapping[str, Any]) -> list[str]:
    """The human lines of one probe result."""
    head = f"provider {data['provider_id']} ({data['kind']}, {data['model'] or 'default model'})"
    if not data["ok"]:
        return [f"{head}: FAILED ({data['reason_code']})", f"hint: {data['hint']}"]
    details = []
    if data["latency_ms"] is not None:
        details.append(f"OK in {data['latency_ms']} ms")
    else:
        details.append("OK")
    if data["prompt_tokens"] is not None and data["completion_tokens"] is not None:
        details.append(
            f"{data['prompt_tokens']} prompt + {data['completion_tokens']} completion tokens"
        )
    lines = [f"{head}: {', '.join(details)}"]
    if data["structured_output"] != "not-tested":
        lines.append(f"structured output: {data['structured_output']}")
    if data["kind"] in LOCAL_DOUBLES:
        lines.append(LOCAL_DOUBLE_LINE)
    if data["ledger_seq"] is not None:
        lines.append(f"recorded in ledger as seq {data['ledger_seq']}")
    return lines


def preflight(
    ctx: typer.Context, cli_ctx: CliContext, provider_id: str, *, accept: bool
) -> EgressConsent:
    """Refuse a probe that must not be sent; returns the consent outcome when it may be.

    Order: unknown id, disabled provider, missing adapter, remote provider when remote use is
    not allowed, then the consent gate.

    Raises:
        UsageError: ``unknown_provider`` or ``provider_disabled`` (exit 2).
        BackendUnavailableError: no adapter for the provider's kind in this build (exit 2).
        PrivacyBlockError: ``remote_not_allowed`` or ``consent_required`` (exit 3).
    """
    llm = cli_ctx.settings.llm
    provider = llm.providers.get(provider_id)
    if provider is None:
        raise UsageError(
            f"unknown provider '{provider_id}'",
            code="unknown_provider",
            hint=f"configured providers: {', '.join(sorted(llm.providers))}",
        )
    if not provider.enabled:
        raise UsageError(f"provider '{provider_id}' is disabled", code="provider_disabled")
    if adapters().get(str(provider.kind)) is None:
        raise BackendUnavailableError(
            f"no adapter for provider kind '{provider.kind}' is available in this build",
            hint="delivered by epic E22",
        )
    if provider.is_remote and (cli_ctx.offline or not llm.allow_remote):
        raise PrivacyBlockError(
            f"provider '{provider_id}' is remote and remote providers are not allowed in this run",
            code="remote_not_allowed",
            hint="drop --offline or set llm.allow_remote = true, or test a local provider",
        )
    return ensure_egress_consent(
        ctx,
        provider_id=provider_id,
        provider=provider,
        level=cli_ctx.privacy_level,
        accept=accept,
    )


def _targets(
    cli_ctx: CliContext, out: Output, provider_id: str | None, everything: bool
) -> list[str]:
    llm = cli_ctx.settings.llm
    if everything:
        return [name for name, provider in llm.providers.items() if provider.enabled]
    if provider_id is not None:
        return [provider_id]
    default = default_provider(cli_ctx, out)
    if default is None:
        raise UsageError(
            "LLM review is disabled (llm.enabled = false); name a provider to test it",
            code="llm_disabled",
        )
    return [default]


@providers_app.command("test")
def test_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    provider_id: Annotated[
        str | None, typer.Argument(help="Provider id; default: the provider a scan would use.")
    ] = None,
    model: Annotated[
        str | None, typer.Option("--model", help="Model to use for this test.")
    ] = None,
    structured: Annotated[
        bool, typer.Option("--structured", help="Also run the structured-output probe.")
    ] = False,
    accept_egress: Annotated[
        bool,
        typer.Option("--accept-egress", help="Approve contacting a remote provider for this run."),
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", min=1.0, help="Seconds allowed per provider.")
    ] = DEFAULT_PROBE_TIMEOUT,
    everything: Annotated[
        bool, typer.Option("--all", help="Test every enabled provider in turn.")
    ] = False,
) -> None:
    """Send a constant probe to a provider and report whether it answers."""
    cli_ctx = get_context(ctx)
    out = get_output(ctx)
    if everything and provider_id is not None:
        raise UsageError("pass a provider id or --all, not both", code="usage")
    targets = _targets(cli_ctx, out, provider_id, everything)
    maybe_show_first_run_notice(ctx)
    # Every refusal happens before the first probe: nothing is sent for a run that is not allowed.
    consents = {name: preflight(ctx, cli_ctx, name, accept=accept_egress) for name in targets}
    probe = load_backend(
        "codekavach.llm.providers", "probe_provider", feature="provider probe", epic="E22"
    )
    results: list[dict[str, Any]] = []
    for name in targets:
        kind = str(cli_ctx.settings.llm.providers[name].kind)
        consent = consents[name]
        if consent.source != "not-required":
            out.info(f"remote egress to {name} accepted via {consent.source}")
        outcome = probe(
            name,
            cli_ctx.settings,
            model=model,
            structured=structured,
            timeout=timeout,
            consent=consent.decision(),
        )
        results.append(probe_data(outcome, provider_id=name, kind=kind))
    lines = [line for data in results for line in probe_lines(data)]
    out.result({"results": results}, human=lambda console: _print(console, lines))
    failed = [data["provider_id"] for data in results if not data["ok"]]
    if failed:
        raise ThresholdExceeded(f"provider test failed: {', '.join(failed)}")
