"""``codekavach config``: show, validate, trust and keyring entries (E03-27, E03-33 to 35).

Owning epic: E03.

``config key set|delete|status`` manage keyring entries under the service ``codekavach``. A key
is never taken from an argument (shell history and process listings, CWE-214): it comes from a
hidden, confirmed prompt or from standard input with ``--stdin``, and no command prints a
value, its length or a prefix (CWE-532). Plaintext keyring backends are refused (code 014).

Trusting a project records its root with the SHA-256 of its configuration file, so the grant
lapses as soon as the file changes (direnv-style). ``trust`` first shows which restricted keys,
escaping paths and loosened privacy settings the file contains (keys only, never values) and asks
for confirmation unless ``--yes``; without a terminal it refuses instead of waiting. E05-19 mounts
``config_app`` on the root application as ``config``.
"""

import json
import os
import re
import sys
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer

from codekavach.cli.console import get_console, get_err_console
from codekavach.cli.errors import UsageError
from codekavach.cli.exit_codes import ExitCode
from codekavach.cli.output import simple_table
from codekavach.config.check import ValidationReport, report_from_error, validate_configuration
from codekavach.config.constants import KEYRING_SERVICE
from codekavach.config.diagnostics import format_issues
from codekavach.config.errors import ConfigError, ConfigIssue, SecretResolutionError
from codekavach.config.keys import (
    KEYRING_UNAVAILABLE_HINT,
    KeyringUnavailableError,
    effective_key_refs,
    open_keyring,
    secret_status,
)
from codekavach.config.loader import load_settings
from codekavach.config.models.root import Settings
from codekavach.config.overrides import parse_set_options
from codekavach.config.paths import find_project_config, project_root_for, user_config_file
from codekavach.config.provenance import Layer
from codekavach.config.render import UnknownSectionError, render_json, render_layer, render_toml
from codekavach.config.toml_source import read_toml
from codekavach.config.trust import TrustStore, project_violations, store_path

if TYPE_CHECKING:
    from codekavach.config.loader import LoadedConfig

config_app = typer.Typer(help="Inspect and manage configuration.", no_args_is_help=True)

REASONS = {
    "CK-CFG-040": "restricted keys",
    "CK-CFG-041": "loosened privacy settings",
}
ESCAPES = "paths that escape the project"


class ListFormat(StrEnum):
    """Output formats of ``trust --list``."""

    text = "text"
    json = "json"


def _store() -> TrustStore:
    try:
        return TrustStore.load(store_path(os.environ))
    except ConfigError as error:
        issue = error.issues[0]
        raise UsageError(
            f"{issue.code.value}: {issue.message} ({issue.source})",
            code="trust_store_corrupt",
            hint=issue.hint,
        ) from None


def _project(path: Path | None) -> tuple[Path, Path]:
    """The project root and its configuration file, discovered like the loader does."""
    start = (path or Path.cwd()).resolve()
    found = find_project_config(start)
    if found is None:
        raise UsageError(
            "no codekavach.toml found for this project",
            code="no_project_config",
            hint="run the command inside the project, or pass its path",
        )
    return project_root_for(start), found


def _user_layer() -> Layer | None:
    path = user_config_file(os.environ)
    if not path.is_file():
        return None
    document = read_toml(path)
    return Layer(name="user", source=str(path), data=document.data, text=document.text)


def _grouped(issues: Sequence[ConfigIssue]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for issue in issues:
        reason = ESCAPES if "escapes" in issue.message else REASONS[issue.code.value]
        key = issue.key or "(unknown key)"
        if key not in groups.setdefault(reason, []):
            groups[reason].append(key)
    return groups


def _list(output_format: ListFormat) -> None:
    entries = _store().entries()
    if output_format is ListFormat.json:
        document = {
            "projects": [
                {"root": e.root, "sha256": e.sha256, "trusted_at": e.trusted_at} for e in entries
            ]
        }
        sys.stdout.write(json.dumps(document, indent=2) + "\n")
        return
    if not entries:
        get_console().print("no trusted projects", markup=False)
        return
    rows = [(e.root, e.sha256[:12], e.trusted_at) for e in entries]
    get_console().print(simple_table(("project", "sha256", "trusted at"), rows))


@config_app.command("trust")
def trust(
    path: Annotated[Path | None, typer.Argument(help="Project directory (default: here).")] = None,
    yes: Annotated[bool, typer.Option("--yes", help="Trust without asking.")] = False,
    list_: Annotated[
        bool, typer.Option("--list", help="List trusted projects instead of trusting one.")
    ] = False,
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Format of --list.")
    ] = ListFormat.text,
) -> None:
    """Trust a project's configuration file, as it is now."""
    if list_:
        _list(output_format)
        return
    store = _store()
    root, config_file = _project(path)
    document = read_toml(config_file, confine_to=root.resolve())
    layer = Layer(
        name="project",
        source=str(config_file),
        data=document.data,
        text=document.text,
        sha256=document.sha256,
    )
    issues = project_violations(layer, project_root=root, user=_user_layer())
    console = get_err_console()
    console.print(f"project: {root}", markup=False)
    console.print(f"file:    {config_file}", markup=False)
    groups = _grouped(issues)
    if not groups:
        console.print("the file sets nothing that needs trust", markup=False)
    for reason, keys in groups.items():
        console.print(f"{reason}:", markup=False)
        for key in keys:
            console.print(f"  {key}", markup=False)
    if not yes:
        if not sys.stdin.isatty():
            raise UsageError(
                "standard input is not a terminal, so trust cannot be confirmed",
                code="confirmation_required",
                hint="review the file, then run again with --yes",
            )
        if not typer.confirm("Trust this configuration file as it is now?", default=False):
            raise typer.Abort
    store.grant(root, document.sha256)
    get_console().print(f"trusted {root}", markup=False)


@config_app.command("untrust")
def untrust(
    path: Annotated[Path | None, typer.Argument(help="Project directory (default: here).")] = None,
) -> None:
    """Forget the trust granted to a project."""
    store = _store()
    root = project_root_for((path or Path.cwd()).resolve())
    if store.revoke(root):
        get_console().print(f"no longer trusted: {root}", markup=False)
    else:
        get_console().print(f"was not trusted: {root}", markup=False)


# --- config key: OS keyring entries (E03-33) ---------------------------------------------------

KEY_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SERVICE_NAME = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")

key_app = typer.Typer(
    help=(
        "Store API keys in the OS keyring. The value is read from a hidden prompt or from "
        "standard input, never from an argument. Automation: "
        'printf %s "$KEY" | codekavach config key set primary --stdin'
    ),
    no_args_is_help=True,
)
config_app.add_typer(key_app, name="key")


def check_key_name(name: str) -> str:
    """``name`` when it is a valid entry name (it may equal a provider id)."""
    if not KEY_NAME.match(name):
        raise UsageError(
            "key names use a lower-case letter, then up to 31 lower-case letters, digits or _",
            code="invalid_key_name",
        )
    return name


def _check_service(service: str) -> str:
    if not SERVICE_NAME.match(service):
        raise UsageError("invalid keyring service name", code="invalid_key_name")
    return service


def _keyring(ref: str) -> Any:
    try:
        return open_keyring(ref)
    except KeyringUnavailableError:
        raise UsageError(
            "no OS keyring is available in this session",
            code="keyring_unavailable",
            hint=KEYRING_UNAVAILABLE_HINT,
        ) from None
    except SecretResolutionError as error:
        issue = error.issues[0]
        raise UsageError(
            f"{issue.code.value}: {issue.message}", code="keyring_insecure", hint=issue.hint
        ) from None


def _read_secret(from_stdin: bool) -> str:
    if from_stdin:
        value = sys.stdin.read()
        if value.endswith("\r\n"):
            value = value[:-2]
        elif value.endswith("\n"):
            value = value[:-1]
    elif not sys.stdin.isatty():
        raise UsageError(
            "standard input is not a terminal, so the key cannot be prompted for",
            code="prompt_unavailable",
            hint="pipe the key in with --stdin",
        )
    else:
        value = typer.prompt("Key", hide_input=True, confirmation_prompt=True)
    if not value:
        raise UsageError("the key is empty", code="empty_key")
    return value


@key_app.command("set")
def key_set(
    name: Annotated[str, typer.Argument(help="Entry name, usually the provider id.")],
    service: Annotated[str, typer.Option("--service", help="Keyring service.")] = KEYRING_SERVICE,
    stdin: Annotated[
        bool, typer.Option("--stdin", help="Read the key from standard input.")
    ] = False,
) -> None:
    """Store a key in the OS keyring and print the reference to use."""
    check_key_name(name)
    _check_service(service)
    ref = f"keyring:{service}/{name}"
    keyring = _keyring(ref)
    value = _read_secret(stdin)
    try:
        keyring.set_password(service, name, value)
    except Exception:  # noqa: BLE001 - every backend failure means the key was not stored
        raise UsageError(
            "the keyring refused to store the key",
            code="keyring_unavailable",
            hint=KEYRING_UNAVAILABLE_HINT,
        ) from None
    get_console().print(f'Stored. Reference it as: api_key = "{ref}"', markup=False)


@key_app.command("delete")
def key_delete(
    name: Annotated[str, typer.Argument(help="Entry name.")],
    service: Annotated[str, typer.Option("--service", help="Keyring service.")] = KEYRING_SERVICE,
    yes: Annotated[bool, typer.Option("--yes", help="Delete without asking.")] = False,
) -> None:
    """Remove a key from the OS keyring; deleting a missing entry is not an error."""
    check_key_name(name)
    _check_service(service)
    keyring = _keyring(f"keyring:{service}/{name}")
    if keyring.get_password(service, name) is None:
        get_console().print(f"no keyring entry {service}/{name}; nothing to delete", markup=False)
        return
    if not yes:
        if not sys.stdin.isatty():
            raise UsageError(
                "standard input is not a terminal, so deletion cannot be confirmed",
                code="confirmation_required",
                hint="run again with --yes",
            )
        if not typer.confirm(f"Delete keyring entry {service}/{name}?", default=False):
            raise typer.Abort
    keyring.delete_password(service, name)
    get_console().print(f"deleted keyring entry {service}/{name}", markup=False)


def _row(group: str, name: str, kind: str, ref: str, state: str) -> dict[str, str]:
    return {"group": group, "name": name, "kind": kind, "ref": ref, "state": state}


def _status_rows(loaded: "LoadedConfig") -> list[dict[str, str]]:
    root = loaded.project_root
    rows: list[dict[str, str]] = []
    for provider_id, provider in loaded.settings.llm.providers.items():
        if not provider.enabled:
            continue
        kind = str(provider.kind)
        refs = effective_key_refs(kind, provider.api_key)
        if not refs:
            rows.append(_row("provider", provider_id, kind, "", "-"))
        for ref in refs:
            state = secret_status(ref, project_root=root).state
            rows.append(_row("provider", provider_id, kind, ref, state))
    github = loaded.settings.integrations.github
    if github.enabled:
        rows.extend(
            _row("github", "token", "", ref, secret_status(ref, project_root=root).state)
            for ref in effective_key_refs("github", github.token)
        )
    return rows


@key_app.command("status")
def key_status(
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Output format.")
    ] = ListFormat.text,
) -> None:
    """Show which references each enabled provider and integration would try, and their state."""
    rows = _status_rows(load_settings(target=Path.cwd()))
    if output_format is ListFormat.json:
        sys.stdout.write(json.dumps({"entries": rows}, indent=2) + "\n")
        return
    if not rows:
        get_console().print("no enabled provider or integration needs a key", markup=False)
        return
    table = [
        (
            row["group"],
            row["name"],
            row["kind"],
            row["ref"] or "(no key required)",
            row["state"] if row["state"] == "-" else row["state"].replace("-", " "),
        )
        for row in rows
    ]
    get_console().print(simple_table(("", "name", "kind", "reference", "state"), table))


# --- config show (E03-34) ----------------------------------------------------------------------

LAYER_NAMES = ("default", "user", "project", "profile", "env", "cli")
REVEAL_WARNING = (
    "warning: --reveal-domain-terms is set; this output contains client vocabulary "
    "(privacy.domain_terms). Do not paste it into third-party systems."
)


class ShowFormat(StrEnum):
    """Output formats of ``config show``."""

    toml = "toml"
    json = "json"


def _load_for_show(
    target: Path | None,
    *,
    config_file: Path | None,
    profile: str | None,
    use_user_config: bool,
    set_values: Sequence[str],
    trust_project_config: bool,
) -> "LoadedConfig":
    try:
        return load_settings(
            target=target,
            config_file=config_file,
            profile=profile,
            cli_overrides=parse_set_options(list(set_values)) if set_values else None,
            use_user_config=use_user_config,
            trust_project_config=trust_project_config,
        )
    except ConfigError as error:
        sys.stderr.write(format_issues(error.issues) + "\n")
        raise typer.Exit(ExitCode.USAGE) from None


def _layer_text(loaded: "LoadedConfig", name: str, fmt: ShowFormat) -> str:
    if name == "default":
        layer = Layer(name="default", source="defaults", data=Settings().model_dump(mode="json"))
    else:
        found = [layer for layer in loaded.layers if layer.name == name]
        if not found:
            sys.stderr.write(f"note: the {name} layer contributes nothing to this run\n")
            return "{}\n" if fmt is ShowFormat.json else ""
        layer = found[-1]
    return render_layer(layer, fmt=fmt.value)


@config_app.command("show")
def show(  # noqa: PLR0917 - the documented option set of the command
    target: Annotated[
        Path | None, typer.Argument(help="Project directory (default: here).")
    ] = None,
    effective: Annotated[
        bool, typer.Option("--effective", help="Show the effective configuration (default).")
    ] = True,
    layer: Annotated[
        str | None,
        typer.Option("--layer", help="Show one layer: default, user, project, profile, env, cli."),
    ] = None,
    output_format: Annotated[
        ShowFormat, typer.Option("--format", help="Output format.")
    ] = ShowFormat.toml,
    origin: Annotated[
        bool, typer.Option("--origin", help="Annotate every key with where its value came from.")
    ] = False,
    section: Annotated[
        str | None, typer.Option("--section", help="Show one top-level table only.")
    ] = None,
    check_secrets: Annotated[
        bool, typer.Option("--check-secrets", help="Report whether each key reference resolves.")
    ] = False,
    reveal_domain_terms: Annotated[
        bool,
        typer.Option("--reveal-domain-terms", help="Print privacy.domain_terms in clear."),
    ] = False,
    config_file: Annotated[
        Path | None, typer.Option("--config", help="Explicit project configuration file.")
    ] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="Profile to apply.")] = None,
    no_user_config: Annotated[
        bool, typer.Option("--no-user-config", help="Ignore the user configuration file.")
    ] = False,
    set_values: Annotated[
        list[str] | None, typer.Option("--set", help="Override one key: KEY=VALUE (TOML).")
    ] = None,
    trust_project_config: Annotated[
        bool,
        typer.Option("--trust-project-config", help="Trust restricted project keys this run."),
    ] = False,
) -> None:
    """Print the configuration in force, masked, optionally with the origin of every key."""
    del effective  # the default mode; accepted so that the documented spelling works
    if layer is not None and layer not in LAYER_NAMES:
        raise UsageError(
            f"unknown layer; choose one of: {', '.join(LAYER_NAMES)}", code="unknown_layer"
        )
    loaded = _load_for_show(
        target,
        config_file=config_file,
        profile=profile,
        use_user_config=not no_user_config,
        set_values=set_values or [],
        trust_project_config=trust_project_config,
    )
    if layer is not None:
        sys.stdout.write(_layer_text(loaded, layer, output_format))
        return
    secrets = _status_rows(loaded) if check_secrets else None
    if reveal_domain_terms:
        sys.stderr.write(REVEAL_WARNING + "\n")
    try:
        if output_format is ShowFormat.json:
            text = render_json(
                loaded, section=section, reveal_domain_terms=reveal_domain_terms, secrets=secrets
            )
        else:
            text = render_toml(
                loaded,
                origins=origin,
                section=section,
                reveal_domain_terms=reveal_domain_terms,
                secrets=secrets,
            )
    except UnknownSectionError:
        raise UsageError(
            "--section names no top-level table of the settings", code="unknown_section"
        ) from None
    sys.stdout.write(text)


# --- config validate (E03-35) ------------------------------------------------------------------


def _summary(report: ValidationReport) -> str:
    def plural(count: int, word: str) -> str:
        return f"{count} {word}" if count == 1 else f"{count} {word}s"

    if report.valid:
        details = [f"profile: {report.profile or 'none'}"]
        if report.warnings:
            details.append(plural(len(report.warnings), "warning"))
        return f"configuration is valid ({', '.join(details)})"
    return (
        f"configuration is invalid: {plural(len(report.errors), 'error')}, "
        f"{plural(len(report.warnings), 'warning')}"
    )


@config_app.command(
    "validate",
    epilog=(
        "Exit codes: 0 valid; 2 invalid; 1 only with --strict, meaning warnings are present. "
        "Refusals of whole layers (plaintext secrets, project trust) are reported first and on "
        "their own; issues of one validation stage are reported together. "
        "Pre-commit: codekavach config validate --strict --no-user-config"
    ),
)
def validate(  # noqa: PLR0917 - the documented option set of the command
    target: Annotated[
        Path | None, typer.Argument(help="Project directory (default: here).")
    ] = None,
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Output format.")
    ] = ListFormat.text,
    strict: Annotated[
        bool, typer.Option("--strict", help="Exit 1 when warnings are present.")
    ] = False,
    check_secrets: Annotated[
        bool, typer.Option("--check-secrets", help="Resolve the keys that a scan would use.")
    ] = False,
    config_file: Annotated[
        Path | None, typer.Option("--config", help="Explicit project configuration file.")
    ] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="Profile to apply.")] = None,
    no_user_config: Annotated[
        bool, typer.Option("--no-user-config", help="Ignore the user configuration file.")
    ] = False,
    set_values: Annotated[
        list[str] | None, typer.Option("--set", help="Override one key: KEY=VALUE (TOML).")
    ] = None,
    trust_project_config: Annotated[
        bool,
        typer.Option("--trust-project-config", help="Trust restricted project keys this run."),
    ] = False,
) -> None:
    """Check the configuration a scan would use, without scanning anything."""
    loader_kwargs: dict[str, Any] = {
        "target": target,
        "config_file": config_file,
        "profile": profile,
        "use_user_config": not no_user_config,
        "trust_project_config": trust_project_config,
    }
    try:
        if set_values:
            loader_kwargs["cli_overrides"] = parse_set_options(list(set_values))
    except ConfigError as error:
        report = report_from_error(error, **loader_kwargs)
    else:
        report = validate_configuration(check_secrets=check_secrets, **loader_kwargs)
    if output_format is ListFormat.json:
        sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
    else:
        issues = [*report.errors, *report.warnings]
        if issues:
            sys.stderr.write(format_issues(issues) + "\n")
        sys.stdout.write(_summary(report) + "\n")
    if not report.valid:
        raise typer.Exit(ExitCode.USAGE)
    if strict and report.warnings:
        raise typer.Exit(ExitCode.FINDINGS)
