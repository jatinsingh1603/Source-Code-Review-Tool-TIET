"""The consent gate: a person approves remote egress before any pipeline work starts (E05-13).

Owning epic: E05.

CodeKavach does not contact a remote LLM provider until someone has said yes for that provider
and privacy level. The check is a pre-flight step of ``scan``: a refused run costs nothing and
sends nothing. The gate can only add a refusal. Every path that cannot positively establish
consent (no terminal, an unreadable or malformed store, an unknown file version, a grant that
does not match) ends in exit 3 before the pipeline runs (I4).

Consent comes from exactly three places: the user's own state file
(``<user config dir>/consent.json``), ``--accept-egress`` typed for this invocation, or the
process variable ``CODEKAVACH_ACCEPT_EGRESS=1``. Configuration files cannot grant it: the
``codekavach.toml`` of the repository being scanned is attacker-controlled content in the threat
model (ARCHITECTURE section 6.4). The store holds provider metadata and timestamps only.

This gate is an accountability control of the CLI. It does not replace the egress guard, which
still requires a ticket for every send (I1); the outcome reaches the core only as
``ConsentDecision`` through ``run_scan(consent=...)``.
"""

import contextlib
import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal

import typer
from rich.console import Console, RenderableType
from rich.panel import Panel
from rich.text import Text
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli._version import get_version
from codekavach.cli.console import get_err_console
from codekavach.cli.context import get_context
from codekavach.cli.errors import PrivacyBlockError, UsageError
from codekavach.cli.onboarding import LEVEL_LINES
from codekavach.cli.output import get_output, simple_table
from codekavach.cli.prompts import confirm, is_interactive
from codekavach.config import Settings
from codekavach.config.models.llm import ProviderSettings
from codekavach.config.paths import user_config_dir
from codekavach.core.models import PrivacyLevel

if TYPE_CHECKING:
    from codekavach.core.pipeline.context import ConsentDecision

CONSENT_FILE: Final = "consent.json"
STORE_VERSION: Final = 1
STORE_FILE_MODE: Final = 0o600
STORE_DIR_MODE: Final = 0o700
ACCEPT_VARIABLE: Final = "CODEKAVACH_ACCEPT_EGRESS"
PANEL_TITLE: Final = "Remote egress"
DISCLOSURE: Final = (
    "Payloads are slices with secrets and personal data replaced by placeholders and internal "
    "names pseudonymised. The provider still sees code structure, public API names and literal "
    "shapes. Every payload is recorded in the local ledger; run `codekavach privacy inspect` to "
    "read them."
)

ConsentSource = Literal["not-required", "stored", "flag", "env"]


@dataclass(frozen=True)
class ConsentGrant:
    """One approval: this provider, as it was configured, at this level or a stricter one."""

    provider_id: str
    kind: str
    host: str | None
    trust_tier: str
    level: PrivacyLevel
    granted_at: datetime
    codekavach_version: str

    def to_json(self) -> dict[str, str | None]:
        """The stored form."""
        return {
            "provider_id": self.provider_id,
            "kind": self.kind,
            "host": self.host,
            "trust_tier": self.trust_tier,
            "level": self.level.value,
            "granted_at": self.granted_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "codekavach_version": self.codekavach_version,
        }

    @classmethod
    def from_json(cls, document: object) -> "ConsentGrant":
        """Parse one stored grant.

        Raises:
            ValueError, KeyError, TypeError: the entry is not a valid grant.
        """
        if not isinstance(document, dict):
            raise TypeError("a grant must be an object")
        host = document["host"]
        texts = [document[key] for key in ("provider_id", "kind", "trust_tier")]
        if not all(isinstance(text, str) and text for text in texts):
            raise TypeError("provider_id, kind and trust_tier must be non-empty strings")
        if host is not None and not isinstance(host, str):
            raise TypeError("host must be a string or null")
        granted_at = datetime.fromisoformat(str(document["granted_at"]))
        if granted_at.tzinfo is None:
            raise ValueError("granted_at must carry a time zone")
        return cls(
            provider_id=texts[0],
            kind=texts[1],
            host=host,
            trust_tier=texts[2],
            level=PrivacyLevel(document["level"]),
            granted_at=granted_at,
            codekavach_version=str(document.get("codekavach_version", "")),
        )


def consent_path(env: Mapping[str, str]) -> Path:
    """``consent.json`` in the user configuration directory (honours ``CODEKAVACH_HOME``)."""
    return user_config_dir(env) / CONSENT_FILE


@dataclass(frozen=True)
class ConsentStore:
    """The grants of one user. A store that cannot be read holds no grant (fail closed)."""

    path: Path
    grants: tuple[ConsentGrant, ...] = ()
    readable: bool = True

    @classmethod
    def load(cls, env: Mapping[str, str]) -> "ConsentStore":
        """The stored grants; a missing file is empty, an invalid one is empty and unreadable."""
        path = consent_path(env)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return cls(path)
        except OSError:
            return cls(path, readable=False)
        try:
            document = json.loads(raw)
            if not isinstance(document, dict) or document.get("version") != STORE_VERSION:
                raise ValueError("unknown store version")
            entries = document["grants"]
            if not isinstance(entries, list):
                raise TypeError("grants must be a list")
            return cls(path, tuple(ConsentGrant.from_json(entry) for entry in entries))
        except (ValueError, KeyError, TypeError, RecursionError):
            return cls(path, readable=False)

    def save(self) -> None:
        """Write the store atomically with mode 0o600; the old file stays valid on failure.

        Raises:
            OSError: the store cannot be written.
        """
        document = {"version": STORE_VERSION, "grants": [grant.to_json() for grant in self.grants]}
        path = self.path
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        path.parent.mkdir(mode=STORE_DIR_MODE, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            with os.fdopen(os.open(temporary, flags, STORE_FILE_MODE), "wb") as handle:
                handle.write((json.dumps(document, indent=2) + "\n").encode("utf-8"))
            temporary.replace(path)
        except BaseException:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise

    def with_grant(self, grant: ConsentGrant) -> "ConsentStore":
        """A store in which ``grant`` replaces earlier grants for the same provider identity."""
        kept = tuple(item for item in self.grants if _identity(item) != _identity(grant))
        return ConsentStore(self.path, (*kept, grant))

    def without(self, provider_id: str | None) -> "ConsentStore":
        """A store without the grants of ``provider_id`` (``None`` removes every grant)."""
        if provider_id is None:
            return ConsentStore(self.path)
        kept = tuple(item for item in self.grants if item.provider_id != provider_id)
        return ConsentStore(self.path, kept)


def _identity(grant: ConsentGrant) -> tuple[str, str, str | None, str]:
    return grant.provider_id, grant.kind, grant.host, grant.trust_tier


def consent_required(provider: ProviderSettings, settings: Settings) -> bool:
    """True when using ``provider`` under ``settings`` would send payloads off the machine.

    False when the LLM is disabled, when remote providers are not allowed in this run
    (``--offline``), when the provider is not remote (``mock``, ``replay``, trust tier
    ``local``), or when the effective level is L0.
    """
    if not settings.llm.enabled or not settings.llm.allow_remote:
        return False
    if settings.privacy.level.sends_nothing_external:
        return False
    return provider.is_remote


def find_grant(
    store: ConsentStore, provider_id: str, provider: ProviderSettings, level: PrivacyLevel
) -> ConsentGrant | None:
    """The stored grant that covers this request, or ``None``.

    A grant covers a request when the provider id, kind, host and trust tier are equal and the
    requested level is at least as strict as the granted one (L1 < L2 < L3 < L4 < L0): a grant at
    L3 covers L3 and L4, a run at L2 asks again, and so does a changed host or kind.
    """
    wanted = (provider_id, provider.kind.value, provider.host, provider.effective_trust_tier.value)
    for grant in store.grants:
        if _identity(grant) == wanted and level.at_least(grant.level):
            return grant
    return None


@dataclass(frozen=True)
class EgressConsent:
    """How this invocation may use the provider."""

    source: ConsentSource

    def decision(self) -> "ConsentDecision | None":
        """What ``run_scan(consent=...)`` receives; ``None`` when no consent is involved."""
        from codekavach.core.pipeline.context import ConsentDecision  # noqa: PLC0415

        if self.source == "not-required":
            return None
        if self.source == "stored":
            return ConsentDecision(granted=True, source="user-file")
        return ConsentDecision(granted=True, source=self.source)


def consent_summary(
    *, provider_id: str, provider: ProviderSettings, model: str | None, level: PrivacyLevel
) -> RenderableType:
    """The panel shown before the question."""
    lines = [
        f"Provider: {provider_id} (kind {provider.kind.value}, host {provider.host or 'default'})",
        f"Model: {model or 'provider default'}",
        f"Privacy level: {level.value}. {LEVEL_LINES[level]}",
        DISCLOSURE,
    ]
    return Panel(Text("\n".join(lines)), title=PANEL_TITLE, title_align="left")


def question(provider_id: str, provider: ProviderSettings, level: PrivacyLevel) -> str:
    """The yes/no question of the gate."""
    host = provider.host or "default host"
    return f"Send sanitised payloads to {provider_id} ({host}) at level {level.value}?"


def new_grant(provider_id: str, provider: ProviderSettings, level: PrivacyLevel) -> ConsentGrant:
    """A grant for ``provider`` as it is configured now."""
    return ConsentGrant(
        provider_id=provider_id,
        kind=provider.kind.value,
        host=provider.host,
        trust_tier=provider.effective_trust_tier.value,
        level=level,
        granted_at=datetime.now(UTC),
        codekavach_version=get_version(),
    )


def refusal(provider_id: str, level: PrivacyLevel) -> PrivacyBlockError:
    """The error of a run without consent (exit 3)."""
    return PrivacyBlockError(
        f"remote provider '{provider_id}' has not been approved for level {level.value}",
        code="consent_required",
        hint=(
            f"run 'codekavach privacy consent grant --provider {provider_id}' on a terminal, "
            "or pass --accept-egress for this run"
        ),
    )


def ensure_egress_consent(
    ctx: click.Context,
    *,
    provider_id: str,
    provider: ProviderSettings,
    level: PrivacyLevel,
    accept: bool,
    interactive: bool = True,
) -> EgressConsent:
    """Establish consent for this run or refuse it.

    Order: not required; a matching stored grant; ``accept`` (the flag) or
    ``CODEKAVACH_ACCEPT_EGRESS=1``, which store nothing; a question on a terminal, which stores a
    grant on yes; otherwise the refusal. With ``interactive=False`` the question is never asked
    and nothing is stored (``doctor`` diagnoses and changes nothing): without a grant, the flag or
    the variable the result is the refusal.

    Raises:
        PrivacyBlockError: ``consent_required`` (exit 3); nothing has run.
    """
    cli_ctx = get_context(ctx)
    if not consent_required(provider, cli_ctx.settings):
        return EgressConsent("not-required")
    store = ConsentStore.load(os.environ)
    if find_grant(store, provider_id, provider, level) is not None:
        return EgressConsent("stored")
    if accept:
        return EgressConsent("flag")
    if os.environ.get(ACCEPT_VARIABLE) == "1":
        return EgressConsent("env")
    if not interactive or not is_interactive(ctx):
        raise refusal(provider_id, level)
    model = cli_ctx.settings.llm.model or provider.model
    get_err_console().print(
        consent_summary(provider_id=provider_id, provider=provider, model=model, level=level)
    )
    if not confirm(ctx, question(provider_id, provider, level)):
        raise refusal(provider_id, level)
    try:
        store.with_grant(new_grant(provider_id, provider, level)).save()
    except OSError:
        raise refusal(provider_id, level) from None
    return EgressConsent("stored")


consent_app = typer.Typer(
    help="Show, grant and revoke consent for sending payloads to remote providers.",
    no_args_is_help=True,
)


def _grant_rows(store: ConsentStore) -> list[list[str]]:
    return [
        [
            grant.provider_id,
            grant.kind,
            grant.host or "default",
            grant.trust_tier,
            grant.level.value,
            str(grant.to_json()["granted_at"]),
        ]
        for grant in store.grants
    ]


@consent_app.command("status")
def status_command(ctx: typer.Context) -> None:
    """List the recorded grants."""
    out = get_output(ctx)
    store = ConsentStore.load(os.environ)
    if not store.readable:
        out.warn(
            "consent_store_invalid",
            "the consent store cannot be read; it is treated as empty",
            hint="grant consent again to rewrite it",
        )
    data: dict[str, Any] = {
        "grants": [grant.to_json() for grant in store.grants],
        "path": str(store.path),
    }

    def render(console: Console) -> None:
        if not store.grants:
            console.print("no consent has been recorded", markup=False)
        else:
            headers = ["Provider", "Kind", "Host", "Trust tier", "Level", "Granted at"]
            console.print(simple_table(headers, _grant_rows(store)))
        console.print(f"store: {store.path}", markup=False, soft_wrap=True)

    out.result(data, human=render)


@consent_app.command("grant")
def grant_command(
    ctx: typer.Context,
    provider_id: Annotated[str, typer.Option("--provider", help="Provider id to approve.")],
    level: Annotated[
        str | None,
        typer.Option("--level", help="Least strict level to approve; default: effective level."),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", help="Approve without asking.")] = False,
) -> None:
    """Approve sending sanitised payloads to a remote provider at a level or stricter."""
    cli_ctx = get_context(ctx)
    out = get_output(ctx)
    provider = cli_ctx.settings.llm.providers.get(provider_id)
    if provider is None:
        raise UsageError(f"unknown provider '{provider_id}'", code="unknown_provider")
    try:
        granted_level = PrivacyLevel(level.upper()) if level else cli_ctx.privacy_level
    except ValueError:
        raise UsageError("--level must be one of L0, L1, L2, L3, L4", code="usage") from None
    if not provider.is_remote or granted_level.sends_nothing_external:
        out.info(f"provider {provider_id} at {granted_level.value} sends nothing off the machine")
        out.result({"granted": False, "reason": "not-required", "path": None})
        return
    model = cli_ctx.settings.llm.model or provider.model
    if is_interactive(ctx):
        get_err_console().print(
            consent_summary(
                provider_id=provider_id, provider=provider, model=model, level=granted_level
            )
        )
    if not confirm(ctx, question(provider_id, provider, granted_level), assume_yes=yes):
        raise UsageError("consent was not granted", code="not_confirmed", hint="re-run with --yes")
    grant = new_grant(provider_id, provider, granted_level)
    store = ConsentStore.load(os.environ).with_grant(grant)
    store.save()
    out.result(
        {"granted": True, "grant": grant.to_json(), "path": str(store.path)},
        human=lambda console: console.print(
            f"consent recorded for {provider_id} at {granted_level.value} and stricter",
            markup=False,
        ),
    )


@consent_app.command("revoke")
def revoke_command(
    ctx: typer.Context,
    provider_id: Annotated[
        str | None, typer.Option("--provider", help="Provider id whose grants to remove.")
    ] = None,
    everything: Annotated[bool, typer.Option("--all", help="Remove every grant.")] = False,
) -> None:
    """Remove recorded consent; the next remote run asks again."""
    if everything == (provider_id is not None):
        raise UsageError("pass exactly one of --provider and --all", code="usage")
    out = get_output(ctx)
    before = ConsentStore.load(os.environ)
    after = before.without(None if everything else provider_id)
    after.save()
    removed = len(before.grants) - len(after.grants)
    out.result(
        {"removed": removed, "path": str(after.path)},
        human=lambda console: console.print(f"removed {removed} grant(s)", markup=False),
    )
