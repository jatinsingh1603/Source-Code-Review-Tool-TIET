"""The first-run privacy notice: what leaves the machine at the effective level (E05-12).

Owning epic: E05.

The notice is a transparency control, not an enforcement point; the blocking control before the
first remote egress is the consent gate (E05-13). It states what is removed, what is still
disclosed at the effective level, and how to check both, in the measured style of the README's
"Known limits": it does not promise that business logic is fully protected. The text lives in
``LEVEL_LINES`` and the tables below so that the documentation (E41) can reuse it.

The notice is shown once per user. Its state is a timestamp and a version in
``<user config dir>/cli-state.json``, not under the project's ``.codekavach/`` directory, which
can be shipped inside a repository and could otherwise pre-seed the state. It is not shown, and
not marked as shown, under ``--quiet``, ``--json`` or in a non-interactive session: it is for a
person, and a CI run must not consume it.
"""

import contextlib
import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Final

from rich.console import RenderableType
from rich.panel import Panel
from rich.text import Text
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli._version import get_version
from codekavach.cli.console import get_err_console
from codekavach.cli.context import CliContext, get_context
from codekavach.cli.prompts import is_interactive
from codekavach.config.paths import user_config_dir
from codekavach.core.log import get_logger
from codekavach.core.models import PrivacyLevel

STATE_FILE: Final = "cli-state.json"
STATE_VERSION: Final = 1
STATE_FILE_MODE: Final = 0o600
STATE_DIR_MODE: Final = 0o700
NOTICE_TITLE: Final = "CodeKavach privacy notice"

LEVEL_LINES: Final[Mapping[PrivacyLevel, str]] = MappingProxyType(
    {
        PrivacyLevel.L0: "Nothing leaves. Only local engines or a local model.",
        PrivacyLevel.L1: "Secrets and PII replaced by typed placeholders.",
        PrivacyLevel.L2: "L1 plus identifiers, literals and comments pseudonymised.",
        PrivacyLevel.L3: "L2 applied to the minimal slice only (default).",
        PrivacyLevel.L4: "No code; abstract data-flow facts and questions.",
    }
)
_SECRETS: Final = "secrets and personal data (typed placeholders)"
_NAMES: Final = (
    "comments and docstrings, internal identifiers and the domain words inside string literals "
    "(pseudonymised)"
)
REMOVED_LINES: Final[Mapping[PrivacyLevel, str]] = MappingProxyType(
    {
        PrivacyLevel.L0: "nothing is sent at this level.",
        PrivacyLevel.L1: f"{_SECRETS}.",
        PrivacyLevel.L2: f"{_SECRETS}, {_NAMES}.",
        PrivacyLevel.L3: f"{_SECRETS}, {_NAMES}, and all code outside the minimal slice.",
        PrivacyLevel.L4: "all code; only abstract data-flow facts and questions are sent.",
    }
)
_SHAPES: Final = (
    "names of public library and framework APIs, the shape of literals (for example an SQL "
    "skeleton), and the fact that a given kind of secret was present"
)
VISIBLE_LINES: Final[Mapping[PrivacyLevel, str]] = MappingProxyType(
    {
        PrivacyLevel.L0: "nothing leaves the machine.",
        PrivacyLevel.L1: (
            "the code of each candidate with its identifiers, comments and literals, and the "
            "fact that a given kind of secret was present."
        ),
        PrivacyLevel.L2: f"the structure and control flow of the code that is sent, {_SHAPES}.",
        PrivacyLevel.L3: f"the structure and control flow of each slice, {_SHAPES}.",
        PrivacyLevel.L4: "data-flow facts only, no code.",
    }
)
LOCAL_LINE: Final = "the provider is local, so nothing leaves the machine."
DISABLED_LINE: Final = "LLM review is disabled; only local engines run"
STRICTER_LINE: Final = "Path rules and provider trust tiers can make individual files stricter."
MEASURED_LINE: Final = (
    "What a payload still discloses is measured by the evaluation harness, not assumed to be zero."
)
CHECK_LINES: Final = (
    "Check it yourself:",
    "  codekavach privacy inspect         the original next to the exact payload",
    "  codekavach privacy ledger show     every payload recorded for sending",
    "  codekavach privacy ledger verify   the hash chain of the ledger",
)
CONFIRM_LINE: Final = (
    "You will be asked to confirm before the first payload is sent to a remote provider."
)

_log = get_logger("codekavach.cli.onboarding")


@dataclass(frozen=True)
class CliState:
    """Per-user state of the CLI: when the first-run notice was shown, and by which version."""

    first_run_notice_shown_at: datetime | None = None
    codekavach_version: str | None = None

    @property
    def notice_shown(self) -> bool:
        """True once the first-run notice has been shown to this user."""
        return self.first_run_notice_shown_at is not None


def state_path(env: Mapping[str, str]) -> Path:
    """``cli-state.json`` in the user configuration directory (honours ``CODEKAVACH_HOME``)."""
    return user_config_dir(env) / STATE_FILE


def read_cli_state(env: Mapping[str, str]) -> CliState:
    """The stored state; a missing, unreadable or malformed file means "not shown"."""
    try:
        document = json.loads(state_path(env).read_bytes())
        if not isinstance(document, dict) or document.get("version") != STATE_VERSION:
            return CliState()
        shown = datetime.fromisoformat(str(document["first_run_notice_shown_at"]))
        if shown.tzinfo is None:
            return CliState()
        version = document.get("codekavach_version")
        return CliState(shown, version if isinstance(version, str) else None)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return CliState()


def write_cli_state(env: Mapping[str, str], state: CliState) -> None:
    """Store ``state`` atomically with mode 0o600; a failure is logged at DEBUG and ignored."""
    shown = state.first_run_notice_shown_at
    document = {
        "version": STATE_VERSION,
        "first_run_notice_shown_at": (
            shown.astimezone(UTC).isoformat().replace("+00:00", "Z") if shown else None
        ),
        "codekavach_version": state.codekavach_version,
    }
    path = state_path(env)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        path.parent.mkdir(mode=STATE_DIR_MODE, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(temporary, flags, STATE_FILE_MODE), "wb") as handle:
            handle.write((json.dumps(document, indent=2) + "\n").encode("utf-8"))
        temporary.replace(path)
    except OSError as error:
        _log.debug("cli_state_write_failed", error_type=type(error).__name__)
        with contextlib.suppress(OSError):
            temporary.unlink()


def notice_lines(
    *,
    level: PrivacyLevel,
    provider_id: str,
    provider_kind: str,
    is_remote: bool,
    llm_enabled: bool,
    origin: str = "default",
) -> list[str]:
    """The lines of the notice for one effective configuration."""
    lines = [
        f"Effective privacy level: {level.value} (from {origin}). {LEVEL_LINES[level]}",
        STRICTER_LINE,
    ]
    if not llm_enabled:
        return [*lines, DISABLED_LINE, "Nothing is sent to a model.", *CHECK_LINES]
    where = "remote" if is_remote else "local: nothing is transmitted"
    lines.append(f"LLM provider: {provider_id} (kind {provider_kind}, {where})")
    lines.append(f"Removed before anything is sent: {REMOVED_LINES[level]}")
    visible = VISIBLE_LINES[level] if is_remote else LOCAL_LINE
    lines.append(f"Still visible to the provider at this level: {visible}")
    lines.append(MEASURED_LINE)
    lines.extend(CHECK_LINES)
    if is_remote:
        lines.append(CONFIRM_LINE)
    return lines


def build_notice(
    *,
    level: PrivacyLevel,
    provider_id: str,
    provider_kind: str,
    is_remote: bool,
    llm_enabled: bool,
    origin: str = "default",
) -> RenderableType:
    """The notice as a Rich panel titled ``CodeKavach privacy notice``."""
    lines = notice_lines(
        level=level,
        provider_id=provider_id,
        provider_kind=provider_kind,
        is_remote=is_remote,
        llm_enabled=llm_enabled,
        origin=origin,
    )
    return Panel(Text("\n".join(lines)), title=NOTICE_TITLE, title_align="left")


def notice_facts(cli_ctx: CliContext) -> dict[str, object]:
    """What the notice describes for the effective settings (loads the configuration)."""
    from codekavach.cli.scan import resolve_provider  # noqa: PLC0415 - scan imports this module

    provider = resolve_provider(cli_ctx)
    origin = cli_ctx.loaded.origins.get("privacy.level")
    return {
        "level": cli_ctx.privacy_level,
        "provider_id": provider.id or "none",
        "provider_kind": provider.kind or "none",
        "is_remote": provider.remote,
        "llm_enabled": cli_ctx.settings.llm.enabled,
        "origin": origin.layer if origin is not None else "default",
    }


def notice_for(cli_ctx: CliContext) -> RenderableType:
    """The notice for the effective settings of this invocation."""
    return build_notice(**notice_facts(cli_ctx))  # type: ignore[arg-type]


def maybe_show_first_run_notice(ctx: click.Context) -> bool:
    """Print the notice on stderr the first time a person runs an egress-capable command.

    Returns whether it was shown. Nothing is shown or recorded under ``--quiet``, ``--json`` or
    in a non-interactive session.
    """
    cli_ctx = get_context(ctx)
    if cli_ctx.quiet or cli_ctx.json_mode or not is_interactive(ctx):
        return False
    if read_cli_state(os.environ).notice_shown:
        return False
    get_err_console().print(notice_for(cli_ctx))
    write_cli_state(
        os.environ,
        CliState(first_run_notice_shown_at=datetime.now(UTC), codekavach_version=get_version()),
    )
    return True
