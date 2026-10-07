"""The checks of ``codekavach doctor`` that look outside the Python process (E05-21).

Owning epic: E05.

``doctor`` (``codekavach.cli.doctor``) holds the framework and the checks that need nothing but
this process. The checks here concern what the settings ask for: external analysis engines, LLM
providers and the prerequisites of the requested report formats. They are built from the loaded
settings when the command starts, one check per enabled engine, per enabled provider and per
requested format, so ``--list`` shows what ``doctor`` would examine in this project. Every check
is optional: a missing engine, key or library is a warning, because CodeKavach's native analysis
and the local test doubles work without them.

Engines. ``engine:<name>`` asks the engine adapter of the plugin registry (epic E14) for its probe,
``adapter.probe(settings)``, and maps the result. The result needs the attributes ``available``
(bool), ``version``, ``path`` or ``image`` (strings or ``None``) and ``install_hint`` (a string or
``None``). The probe starts the engine's version command; this module starts no process itself.

Providers. ``provider:<id>:configured`` reads the secret reference through ``secret_status``
(availability only; no value is read into the output). ``provider:<id>:reachable`` is the one check
that causes an outbound LLM request, and it follows the rules of a scan (I1, I2, I4):

* it runs only with ``--probe-providers``;
* the request is built and sent by the provider adapter through the egress transport (epic E22),
  reached through ``load_backend``; this module opens no connection and builds no request, and the
  probe carries a constant prompt and no client data;
* a remote provider is probed only when ``llm.allow_remote`` is true, the privacy level is not
  ``L0``, and the consent gate of ``codekavach.cli.consent`` is satisfied by a stored grant,
  ``--accept-egress`` or ``CODEKAVACH_ACCEPT_EGRESS=1``. ``doctor`` never asks the question and
  never stores a grant: without consent the check is ``SKIP consent required`` and nothing is sent;
* under ``--offline`` a remote provider is skipped by the runner before this code runs, while a
  local provider (``ollama`` or a loopback server, ``ProviderSettings.is_remote`` is false) is still
  probed, because loopback traffic leaves nothing;
* a failure shows a reason code and its hint, never the text of the transport's error.

Reports. ``report:pdf`` and ``report:fonts`` exist when ``reporting.formats`` names ``pdf``. Epic
E31 supplies ``probe_pdf_prerequisites()`` (an object with ``ok`` and an optional ``detail``) in
``codekavach.report.render.pdf`` and ``find_fonts(script)`` (family names) in
``codekavach.report.render.fonts``; until it lands the checks are ``SKIP not available in this
build``.

Output is pasted into issue trackers. Texts that come from an adapter are limited to one short line
without control characters. The page ``docs/reference/cli-doctor.md`` lists every check.
"""

import functools
import platform
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from pydantic import JsonValue
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli.backends import load_backend
from codekavach.cli.consent import ensure_egress_consent
from codekavach.cli.context import CliContext
from codekavach.cli.doctor import (
    DEFAULT_TIMEOUT_SECONDS,
    Check,
    CheckStatus,
    LocalCheck,
    Outcome,
)
from codekavach.cli.errors import PrivacyBlockError
from codekavach.cli.providers import (
    DISABLED_LINE,
    LOCAL_DOUBLES,
    credential_state,
    probe_data,
)
from codekavach.config.models.reporting import ReportFormat
from codekavach.core.plugins.discovery import discover
from codekavach.core.plugins.policy import apply_policy

if TYPE_CHECKING:
    from codekavach.config import Settings
    from codekavach.config.models.llm import ProviderSettings
    from codekavach.core.pipeline.context import ConsentDecision

ENGINES: Final = "engines"
PROVIDERS: Final = "providers"
REPORT: Final = "report"
CATEGORIES: Final = (ENGINES, PROVIDERS, REPORT)
ENGINE_GROUP: Final = "codekavach.engines"
PROBE_HINT: Final = "use --probe-providers"
UNSELECTED: Final = "not in engines.enabled"
MAX_TEXT: Final = 120
PROBE_TIMEOUT_SHARE: Final = 0.8
SCRIPT_DEVANAGARI: Final = "devanagari"
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f-\x9f]+")

PDF_HINTS: Final[Mapping[str, str]] = {
    "Linux": "install Pango, for example: apt install libpango-1.0-0 libpangoft2-1.0-0",
    "Darwin": "install the Pango library: brew install pango",
    "Windows": "WeasyPrint needs the GTK runtime on Windows; use the devcontainer or WSL 2",
}
PDF_HINT_FALLBACK: Final = "install the Pango and HarfBuzz libraries that WeasyPrint needs"
FONT_HINT: Final = (
    "install a font that covers Devanagari, for example Noto Sans Devanagari "
    "(apt install fonts-noto-core); macOS and Windows ship one"
)
ENGINE_MISSING_HINT: Final = (
    "install the plugin that provides this engine, or remove it from engines.enabled"
)
ENGINE_NOT_FOUND_HINT: Final = "install the engine itself, or remove it from engines.enabled"
KEY_HINT: Final = "set the variable or change the reference; see `codekavach config key status`"
KEYRING_HINT: Final = "install a keyring backend, or use an env: reference for this provider"
CONSENT_HINT: Final = (
    "run `codekavach privacy consent grant --provider {provider}` on a terminal, "
    "or pass --accept-egress"
)

Probe = Callable[[CliContext], Outcome]


def _text(value: object, limit: int = MAX_TEXT) -> str | None:
    """A short single line from ``value``, or ``None`` when it is not a non-empty string."""
    if not isinstance(value, str):
        return None
    line = _CONTROL.sub(" ", value).strip()
    if not line:
        return None
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _check(
    name: str,
    category: str,
    probe: Probe,
    *,
    needs_network: bool = False,
    remediation: str | None = None,
) -> LocalCheck:
    return LocalCheck(
        name, category, probe, required=False, needs_network=needs_network, remediation=remediation
    )


# engines


def engine_adapters(settings: "Settings") -> Mapping[str, object]:
    """The engine adapters of the plugin registry, by name; the ``[plugins]`` policy applies."""
    registry = load_backend(
        "codekavach.core.plugins.registry",
        "registry_from_environment",
        feature="the plugin registry",
        epic="E04",
    )(settings)
    found: Mapping[str, object] = registry.engines()
    return found


def _installed_engine_names(settings: "Settings") -> set[str]:
    """The engines whose plugins may load under the policy; read from metadata, nothing imported."""
    allowed, _disabled = apply_policy(discover((ENGINE_GROUP,)), settings.plugins)
    return {spec.name for spec in allowed}


def _engine_mode(settings: "Settings", name: str) -> str:
    """How the settings treat engine ``name``.

    ``enabled`` (asked for), ``disabled`` (switched off), ``unselected`` (``engines.enabled`` lists
    other engines) or ``implicit`` (nothing names it and ``engines.enabled`` is empty, so every
    installed engine runs).
    """
    engines = settings.engines
    option = engines.options.get(name)
    if option is not None and option.enabled is not None:
        return "enabled" if option.enabled else "disabled"
    if name in engines.disabled:
        return "disabled"
    if name in engines.enabled:
        return "enabled"
    return "unselected" if engines.enabled else "implicit"


def _engine_details(result: object) -> tuple[dict[str, JsonValue], str]:
    """The fields of a probe result that may be shown, and the summary line built from them."""
    version = _text(getattr(result, "version", None))
    path = _text(getattr(result, "path", None))
    image = _text(getattr(result, "image", None))
    shown = {"version": version, "path": path, "image": image}
    details: dict[str, JsonValue] = {"adapter": True}
    details.update({key: value for key, value in shown.items() if value is not None})
    where = path or image
    parts = [part for part in (version, f"at {where}" if where else None) if part]
    return details, " ".join(parts) or "runnable"


def _not_runnable(mode: str, result: object) -> Outcome:
    """The outcome of an engine whose probe found it absent."""
    if mode == "implicit":
        return Outcome(CheckStatus.SKIP, "not installed", {"adapter": True})
    hint = _text(getattr(result, "install_hint", None))
    return Outcome(
        CheckStatus.WARN,
        "enabled, but not installed",
        {"adapter": True},
        remediation=hint or ENGINE_NOT_FOUND_HINT,
    )


def _engine_outcome(
    settings: "Settings", name: str, mode: str, adapters: Callable[[], Mapping[str, object]]
) -> Outcome:
    if mode in {"disabled", "unselected"}:
        return Outcome(CheckStatus.SKIP, "disabled" if mode == "disabled" else UNSELECTED)
    adapter = adapters().get(name)
    probe = getattr(adapter, "probe", None)
    if not callable(probe):
        if mode == "implicit":
            return Outcome(CheckStatus.SKIP, "its adapter is not available")
        return Outcome(
            CheckStatus.WARN,
            "enabled, but no adapter for it is installed",
            {"adapter": False},
            remediation=ENGINE_MISSING_HINT,
        )
    result = probe(settings)
    if getattr(result, "available", False) is not True:
        return _not_runnable(mode, result)
    details, summary = _engine_details(result)
    return Outcome(CheckStatus.PASS, summary, details)


def _engine_check(
    settings: "Settings", name: str, adapters: Callable[[], Mapping[str, object]]
) -> Check:
    mode = _engine_mode(settings, name)

    def probe(_ctx: CliContext) -> Outcome:
        return _engine_outcome(settings, name, mode, adapters)

    return _check(f"engine:{name}", ENGINES, probe)


def engine_checks(settings: "Settings") -> list[Check]:
    """One ``engine:<name>`` check for every engine the settings name or the environment offers.

    With an empty ``engines.enabled`` every installed engine is a candidate: it passes when found
    and is skipped when not, because nothing asked for it. An engine named in ``engines.enabled``
    (or by ``engines.options.<id>.enabled``) that is absent is a warning; a disabled one is a skip.
    """
    engines = settings.engines
    names = set(engines.enabled) | set(engines.disabled) | set(engines.options)
    names |= _installed_engine_names(settings)
    adapters = functools.cache(lambda: engine_adapters(settings))  # the plugins load once
    return [_engine_check(settings, name, adapters) for name in sorted(names)]


# providers


@dataclass(frozen=True)
class ProbePlan:
    """What the command line asks of the provider probe."""

    ctx: click.Context | None = None  # the click context the consent gate needs
    enabled: bool = False  # --probe-providers
    accept: bool = False  # --accept-egress
    timeout: float = DEFAULT_TIMEOUT_SECONDS  # --timeout; the probe gets a share of it


def _configured_outcome(provider: "ProviderSettings", cli_ctx: CliContext) -> Outcome:
    kind = str(provider.kind)
    if not cli_ctx.settings.llm.enabled:
        return Outcome(CheckStatus.SKIP, DISABLED_LINE)
    details: dict[str, JsonValue] = {"kind": kind, "remote": provider.is_remote}
    if kind in LOCAL_DOUBLES:
        return Outcome(CheckStatus.PASS, f"kind {kind}", details)
    state, refs = credential_state(provider, cli_ctx, check=True)
    names: list[JsonValue] = [*refs]
    details.update({"credential": state, "references": names})
    if state == "not-required":
        return Outcome(CheckStatus.PASS, f"kind {kind}, no credential needed", details)
    if state == "set":
        return Outcome(CheckStatus.PASS, f"kind {kind}, credential available", details)
    if state == "backend-unavailable":
        summary = "the keyring backend is unavailable"
        return Outcome(CheckStatus.WARN, summary, details, remediation=KEYRING_HINT)
    summary = f"{refs[0]} is not set" if len(refs) == 1 else f"none of {', '.join(refs)} is set"
    return Outcome(CheckStatus.WARN, summary, details, remediation=KEY_HINT)


def _no_consent(provider_id: str) -> Outcome:
    hint = CONSENT_HINT.format(provider=provider_id)
    return Outcome(CheckStatus.SKIP, "consent required", remediation=hint)


def _consent_for(
    plan: ProbePlan, provider_id: str, provider: "ProviderSettings", cli_ctx: CliContext
) -> tuple[Outcome | None, "ConsentDecision | None"]:
    """``(skip, None)`` without consent, ``(None, decision)`` when the probe may be sent.

    Never asks a question and never stores a grant (``interactive=False``).
    """
    if plan.ctx is None:
        return _no_consent(provider_id), None
    try:
        consent = ensure_egress_consent(
            plan.ctx,
            provider_id=provider_id,
            provider=provider,
            level=cli_ctx.privacy_level,
            accept=plan.accept,
            interactive=False,
        )
    except PrivacyBlockError:
        return _no_consent(provider_id), None
    return None, consent.decision()


def _gate(provider: "ProviderSettings", cli_ctx: CliContext, plan: ProbePlan) -> Outcome | None:
    """The reason not to probe before consent is even asked, or ``None``."""
    settings = cli_ctx.settings
    if not plan.enabled:
        return Outcome(CheckStatus.SKIP, PROBE_HINT)
    if not settings.llm.enabled:
        return Outcome(CheckStatus.SKIP, DISABLED_LINE)
    kind = str(provider.kind)
    if kind in LOCAL_DOUBLES:
        return Outcome(CheckStatus.PASS, f"local {kind} provider; nothing was sent", {"kind": kind})
    if provider.is_remote and not settings.llm.allow_remote:
        return Outcome(CheckStatus.SKIP, "remote providers are not allowed")
    if provider.is_remote and settings.privacy.level.sends_nothing_external:
        level = settings.privacy.level.value
        return Outcome(CheckStatus.SKIP, f"privacy level {level} sends nothing")
    return None


def _reachable_outcome(
    provider_id: str, provider: "ProviderSettings", cli_ctx: CliContext, plan: ProbePlan
) -> Outcome:
    stop = _gate(provider, cli_ctx, plan)
    if stop is not None:
        return stop
    decision = None
    if provider.is_remote:
        skip, decision = _consent_for(plan, provider_id, provider, cli_ctx)
        if skip is not None:
            return skip
    send = load_backend(
        "codekavach.llm.providers", "probe_provider", feature="provider probe", epic="E22"
    )
    kind = str(provider.kind)
    result = send(
        provider_id,
        cli_ctx.settings,
        model=None,
        structured=False,
        timeout=plan.timeout * PROBE_TIMEOUT_SHARE,
        consent=decision,
    )
    data = probe_data(result, provider_id=provider_id, kind=kind)
    latency = data["latency_ms"]
    details: dict[str, JsonValue] = {
        "kind": kind,
        "remote": provider.is_remote,
        "latency_ms": latency,
    }
    if data["ok"]:
        summary = f"answered in {latency} ms" if latency else "answered"
        return Outcome(CheckStatus.PASS, summary, details)
    details["reason"] = data["reason_code"]
    return Outcome(
        CheckStatus.FAIL, f"probe failed: {data['reason_code']}", details, remediation=data["hint"]
    )


def _provider_checks(
    provider_id: str, provider: "ProviderSettings", plan: ProbePlan
) -> list[Check]:
    def configured(cli_ctx: CliContext) -> Outcome:
        return _configured_outcome(provider, cli_ctx)

    def reachable(cli_ctx: CliContext) -> Outcome:
        return _reachable_outcome(provider_id, provider, cli_ctx, plan)

    return [
        _check(f"provider:{provider_id}:configured", PROVIDERS, configured),
        _check(
            f"provider:{provider_id}:reachable",
            PROVIDERS,
            reachable,
            needs_network=provider.is_remote,
        ),
    ]


def provider_checks(settings: "Settings", plan: ProbePlan | None = None) -> list[Check]:
    """``provider:<id>:configured`` and ``provider:<id>:reachable`` for every enabled provider.

    Without ``plan.enabled`` (``--probe-providers``) no ``reachable`` check ever sends anything.
    """
    plan = plan or ProbePlan()
    checks: list[Check] = []
    for provider_id in sorted(settings.llm.providers):
        provider = settings.llm.providers[provider_id]
        if provider.enabled:
            checks.extend(_provider_checks(provider_id, provider, plan))
    return checks


# reports


def _pdf_outcome(_ctx: CliContext) -> Outcome:
    probe = load_backend(
        "codekavach.report.render.pdf",
        "probe_pdf_prerequisites",
        feature="the PDF prerequisite probe",
        epic="E31",
    )
    result = probe()
    if getattr(result, "ok", False) is True:
        return Outcome(CheckStatus.PASS, "WeasyPrint and its libraries load")
    hint = PDF_HINTS.get(platform.system(), PDF_HINT_FALLBACK)
    return Outcome(
        CheckStatus.WARN,
        "PDF reports cannot be produced on this machine",
        {"os": platform.system()},
        remediation=hint,
    )


def _fonts_outcome(_ctx: CliContext) -> Outcome:
    find = load_backend(
        "codekavach.report.render.fonts", "find_fonts", feature="the font probe", epic="E31"
    )
    found = find(SCRIPT_DEVANAGARI)
    families = sorted({family for item in found if (family := _text(item, 60))})
    details: dict[str, JsonValue] = {"script": SCRIPT_DEVANAGARI, "fonts": [*families]}
    if families:
        return Outcome(CheckStatus.PASS, f"{len(families)} font(s) cover Devanagari", details)
    return Outcome(CheckStatus.WARN, "no font covers Devanagari", details, remediation=FONT_HINT)


def report_checks(settings: "Settings") -> list[Check]:
    """``report:pdf`` and ``report:fonts``, when ``reporting.formats`` includes ``pdf``."""
    if ReportFormat.pdf not in settings.reporting.formats:
        return []
    return [
        _check("report:pdf", REPORT, _pdf_outcome),
        _check("report:fonts", REPORT, _fonts_outcome),
    ]


def external_checks(settings: "Settings", plan: ProbePlan | None = None) -> list[Check]:
    """The checks of this module for ``settings``, in the order engines, providers, report."""
    return [*engine_checks(settings), *provider_checks(settings, plan), *report_checks(settings)]


def settings_unavailable() -> list[Check]:
    """One skipped placeholder per category, for a configuration that cannot be loaded.

    Without settings it is not known which engines, providers and formats were asked for. The
    placeholders keep ``--category`` working and point at ``config:valid``, which reports why.
    """

    def skipped(_ctx: CliContext) -> Outcome:
        return Outcome(CheckStatus.SKIP, "the configuration is invalid; see config:valid")

    return [_check(f"{category}:settings", category, skipped) for category in CATEGORIES]
