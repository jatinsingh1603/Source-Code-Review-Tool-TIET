"""``codekavach config``: init, show, validate, path, profiles, trust, key and policy.

Owning epic: E03. The commands come from E03-27 and E03-32 to E03-37.

``config key set|delete|status`` manage keyring entries under the service ``codekavach``. A key
is never taken from an argument (shell history and process listings, CWE-214): it comes from a
hidden, confirmed prompt or from standard input with ``--stdin``, and no command prints a
value, its length or a prefix (CWE-532). Plaintext keyring backends are refused (code 014).

Trusting a project records its root with the SHA-256 of its configuration file, so the grant
lapses as soon as the file changes (direnv-style). ``trust`` first shows which restricted keys,
escaping paths and loosened privacy settings the file contains (keys only, never values) and asks
for confirmation unless ``--yes``; without a terminal it refuses instead of waiting. E05-19 mounts
``config_app`` on the root application as ``config``.

Conventions of the root application (E05-19): the loader options ``--config``, ``--profile``,
``--no-user-config``, ``--trust-project-config`` and ``--set`` are the global options and are read
from ``CliContext``. ``--format`` selects the document of a command; the global ``--json`` puts
the JSON form of that document into the envelope as ``data``. The document is the masked
rendering of this module either way, never the raw settings object.
"""

import contextlib
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from pydantic import ValidationError
from typer._click.core import ParameterSource

from codekavach.cli.console import get_console, get_err_console
from codekavach.cli.context import get_context
from codekavach.cli.errors import InternalError, UsageError
from codekavach.cli.exit_codes import ExitCode
from codekavach.cli.options import globals_of
from codekavach.cli.output import get_output, simple_table
from codekavach.config.check import ValidationReport, report_from_error, validate_configuration
from codekavach.config.constants import KEYRING_SERVICE, PROJECT_FILE_NAME
from codekavach.config.diagnostics import format_issues
from codekavach.config.errors import (
    ConfigError,
    ConfigErrorCode,
    ConfigIssue,
    OrgPolicyError,
    ProfileError,
    SecretResolutionError,
)
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
from codekavach.config.paths import (
    ConfigPaths,
    collect_paths,
    find_project_config,
    project_root_for,
    user_config_file,
)
from codekavach.config.profiles import BUILTIN_PROFILES, list_profiles
from codekavach.config.provenance import Layer
from codekavach.config.render import UnknownSectionError, render_json, render_layer, render_toml
from codekavach.config.starter import render_starter
from codekavach.config.toml_source import read_toml
from codekavach.config.trust import TrustStore, project_violations, store_path

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from codekavach.config.loader import LoadedConfig
    from codekavach.config.orgpolicy.discovery import LoadedOrgPolicy
    from codekavach.config.orgpolicy.model import OrgPolicy

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


def _json_wanted(ctx: typer.Context, output_format: StrEnum) -> bool:
    """Whether the command produces its JSON document.

    The global ``--json`` selects it too; together with another ``--format`` given on the command
    line it is a usage error (``format_conflict``).
    """
    envelope = bool(globals_of(ctx).get("json_mode", False))
    explicit = ctx.get_parameter_source("output_format") is ParameterSource.COMMANDLINE
    if envelope and explicit and output_format.value != "json":
        raise UsageError(
            f"--json cannot be combined with --format {output_format.value}",
            code="format_conflict",
        )
    return envelope or output_format.value == "json"


def _write_json(ctx: typer.Context, document: Any, text: str | None = None) -> None:
    """Write the JSON document: raw on stdout, or as ``data`` of the envelope under ``--json``."""
    if globals_of(ctx).get("json_mode", False):
        get_output(ctx).result(document)
        return
    sys.stdout.write(text if text is not None else json.dumps(document, indent=2) + "\n")


def _loader_options(ctx: typer.Context) -> dict[str, Any]:
    """The global loader options of this invocation, without parsing ``--set``."""
    values = globals_of(ctx)
    return {
        "config_file": values.get("config"),
        "profile": values.get("profile"),
        "use_user_config": not values.get("no_user_config", False),
        "trust_project_config": bool(values.get("trust_project_config", False)),
    }


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
    ctx: typer.Context,
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Output format.")
    ] = ListFormat.text,
) -> None:
    """Show which references each enabled provider and integration would try, and their state."""
    as_json = _json_wanted(ctx, output_format)
    rows = _status_rows(load_settings(target=Path.cwd()))
    if as_json:
        _write_json(ctx, {"entries": rows})
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


def _load_for_show(ctx: typer.Context, target: Path | None) -> "LoadedConfig":
    try:
        overrides = get_context(ctx).cli_overrides
        return load_settings(
            target=target,
            cli_overrides=overrides if overrides.data else None,
            **_loader_options(ctx),
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
    ctx: typer.Context,
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
) -> None:
    """Print the configuration in force, masked, optionally with the origin of every key."""
    del effective  # the default mode; accepted so that the documented spelling works
    as_json = _json_wanted(ctx, output_format)
    if layer is not None and layer not in LAYER_NAMES:
        raise UsageError(
            f"unknown layer; choose one of: {', '.join(LAYER_NAMES)}", code="unknown_layer"
        )
    loaded = _load_for_show(ctx, target)
    if layer is not None:
        text = _layer_text(loaded, layer, ShowFormat.json if as_json else output_format)
        if as_json:
            _write_json(ctx, json.loads(text), text)
        else:
            sys.stdout.write(text)
        return
    secrets = _status_rows(loaded) if check_secrets else None
    if reveal_domain_terms:
        sys.stderr.write(REVEAL_WARNING + "\n")
    try:
        if as_json:
            text = render_json(
                loaded, section=section, reveal_domain_terms=reveal_domain_terms, secrets=secrets
            )
            _write_json(ctx, json.loads(text), text)
            return
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
def validate(
    ctx: typer.Context,
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
) -> None:
    """Check the configuration a scan would use, without scanning anything."""
    as_json = _json_wanted(ctx, output_format)
    loader_kwargs: dict[str, Any] = {"target": target, **_loader_options(ctx)}
    set_values = list(globals_of(ctx).get("set_values", []))
    try:
        if set_values:
            loader_kwargs["cli_overrides"] = parse_set_options(set_values)
    except ConfigError as error:
        report = report_from_error(error, **loader_kwargs)
    else:
        report = validate_configuration(check_secrets=check_secrets, **loader_kwargs)
    if as_json:
        _write_json(ctx, report.to_dict())
    else:
        issues = [*report.errors, *report.warnings]
        if issues:
            sys.stderr.write(format_issues(issues) + "\n")
        sys.stdout.write(_summary(report) + "\n")
    if not report.valid:
        raise typer.Exit(ExitCode.USAGE)
    if strict and report.warnings:
        raise typer.Exit(ExitCode.FINDINGS)


# --- config path and config profiles (E03-36) --------------------------------------------------


def _trust_note(paths: ConfigPaths) -> str | None:
    """``this project: trusted`` or ``untrusted`` for an existing store; never raises."""
    store_entry, project_entry = paths.trust_store, paths.project_config
    if not store_entry.exists or store_entry.path is None:
        return None
    try:
        store = TrustStore.load(store_entry.path)
    except ConfigError:
        return "unreadable"
    if not project_entry.exists or project_entry.path is None or project_entry.note:
        return None
    root = paths.project_root.path or Path.cwd()
    sha256 = hashlib.sha256(project_entry.path.read_bytes()).hexdigest()
    return "this project: trusted" if store.is_trusted(root, sha256) else "this project: untrusted"


def _path_rows(paths: ConfigPaths) -> list[dict[str, Any]]:
    trust_note = _trust_note(paths)
    rows = []
    for entry in paths.entries():
        note = trust_note if entry is paths.trust_store else entry.note
        rows.append(
            {
                "label": entry.label,
                "path": str(entry.path) if entry.path is not None else None,
                "exists": entry.exists,
                "note": note,
            }
        )
    return rows


def _status(row: Mapping[str, Any]) -> str:
    if row["label"] == "project root":
        return ""
    if row["path"] is None:
        return row["note"] or ""
    status = "found" if row["exists"] else "missing"
    return f"{status} ({row['note']})" if row["note"] else status


@config_app.command("path")
def path_command(
    ctx: typer.Context,
    target: Annotated[
        Path | None, typer.Argument(help="Project directory (default: here).")
    ] = None,
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Output format.")
    ] = ListFormat.text,
) -> None:
    """List every location CodeKavach reads, and whether it exists; creates nothing."""
    as_json = _json_wanted(ctx, output_format)
    rows = _path_rows(collect_paths((target or Path.cwd()).resolve(), os.environ))
    if as_json:
        _write_json(ctx, {"paths": rows})
        return
    lines = [f"{row['label']:<20} {row['path'] or '-':<50} {_status(row)}".rstrip() for row in rows]
    sys.stdout.write("\n".join(lines) + "\n")


def _user_defined_profiles(
    target: Path,
) -> tuple[dict[str, Mapping[str, Any]], dict[str, str], list[str]]:
    """Raw ``[profiles.*]`` tables of the user and project files; unparsable files are noted."""
    tables: dict[str, Mapping[str, Any]] = {}
    sources: dict[str, str] = {}
    notes: list[str] = []
    candidates = [user_config_file(os.environ), find_project_config(target)]
    for path in candidates:
        if path is None or not path.is_file():
            continue
        try:
            data = read_toml(path).data
        except ConfigError:
            notes.append(f"note: {path} does not parse; its profiles are skipped")
            continue
        profiles = data.get("profiles")
        for name, table in profiles.items() if isinstance(profiles, Mapping) else ():
            if isinstance(table, Mapping):
                tables[str(name)] = table
                sources[str(name)] = str(path)
    return tables, sources, notes


@config_app.command("profiles")
def profiles_command(
    ctx: typer.Context,
    target: Annotated[
        Path | None, typer.Argument(help="Project directory (default: here).")
    ] = None,
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Output format.")
    ] = ListFormat.text,
) -> None:
    """List the built-in and user-defined profiles."""
    as_json = _json_wanted(ctx, output_format)
    tables, sources, notes = _user_defined_profiles((target or Path.cwd()).resolve())
    for note in notes:
        sys.stderr.write(note + "\n")
    infos = list_profiles(tables, sources=sources)
    rows = [
        {
            "name": info.name,
            "kind": info.kind,
            "defined_in": info.defined_in,
            "extends": info.extends,
            "description": info.description,
        }
        for info in infos
    ]
    if as_json:
        _write_json(ctx, rows)
        return
    table = [
        (info.name, info.kind, info.defined_in, info.extends or "-", info.description or "")
        for info in infos
    ]
    columns = ("name", "kind", "defined in", "extends", "description")
    get_console().print(simple_table(columns, table))


# --- config init (E03-37); E05-19 also registers init_command as the top-level ``init`` ---------

GITIGNORE_ENTRIES = (".codekavach/", "codekavach-report/")
NEXT_STEPS = (
    "Next steps:",
    "  1. Provide a key: export ANTHROPIC_API_KEY=... or codekavach config key set primary",
    "  2. Check the configuration: codekavach config validate",
    "  3. Scan: codekavach scan .",
)


def _check_profile(profile: str) -> bool:
    """Whether ``profile`` is built-in; raise 020 when it is neither built-in nor user-defined."""
    if profile in BUILTIN_PROFILES:
        return True
    user_defined, _, _ = _user_defined_profiles(Path.cwd())
    if profile in user_defined:
        return False
    error = ProfileError.single(
        ConfigErrorCode.CK_CFG_020,
        f"unknown profile; available profiles: {', '.join(sorted(BUILTIN_PROFILES))}",
        key="profile",
    )
    sys.stderr.write(format_issues(error.issues) + "\n")
    raise typer.Exit(ExitCode.USAGE)


def _validate_starter(directory: Path, text: str, temporary: Path) -> None:
    """Load the rendered file as a project file; a failure is a template bug."""
    temporary.write_text(text, encoding="utf-8", newline="\n")
    try:
        load_settings(target=directory, config_file=temporary, use_user_config=False, env={})
    except ConfigError as error:
        raise InternalError(
            "the generated starter file does not validate; please report this bug",
            hint=error.issues[0].code.value,
        ) from None


def _update_gitignore(directory: Path) -> str:
    root = project_root_for(directory)
    if not (root / ".git").exists():
        return "not a git work tree; .gitignore left unchanged"
    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    missing = [entry for entry in GITIGNORE_ENTRIES if entry not in existing.split("\n")]
    if not missing:
        return ".gitignore already ignores the state and report directories"
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(prefix + "\n".join(missing) + "\n")
    return f"added to .gitignore: {', '.join(missing)}"


def init_command(  # noqa: PLR0917 - the documented option set of the command
    path: Annotated[
        Path | None, typer.Argument(help="Directory to write codekavach.toml into.")
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Profile to select in the file.")
    ] = None,
    minimal: Annotated[
        bool, typer.Option("--minimal", help="Only the active settings, without comments.")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing file; keeps a .bak copy.")
    ] = False,
    stdout: Annotated[
        bool, typer.Option("--stdout", help="Print the file instead of writing it.")
    ] = False,
    update_gitignore: Annotated[
        bool,
        typer.Option("--update-gitignore", help="Add the state and report directories."),
    ] = False,
) -> None:
    """Write a commented starter codekavach.toml rendered from the settings models."""
    directory = (path or Path.cwd()).resolve()
    if not directory.is_dir():
        raise UsageError("PATH is not a directory", code="not_a_directory")
    builtin_profile = _check_profile(profile) if profile is not None else True
    text = render_starter(profile=profile, minimal=minimal, project_name=directory.name)
    if stdout:
        sys.stdout.write(text)
        return
    target = directory / PROJECT_FILE_NAME
    if target.exists() and not force:
        raise UsageError(
            f"{target} already exists", code="config_exists", hint="use --force to replace it"
        )
    descriptor, name = tempfile.mkstemp(dir=directory, prefix=".codekavach-", suffix=".toml")
    os.close(descriptor)
    temporary = Path(name)
    try:
        checked = (
            text
            if builtin_profile
            else render_starter(minimal=minimal, project_name=directory.name)
        )
        _validate_starter(directory, checked, temporary)
        temporary.write_text(text, encoding="utf-8", newline="\n")
        if sys.platform != "win32":
            temporary.chmod(0o644)
        if target.exists():
            shutil.copy2(target, target.with_name(f"{PROJECT_FILE_NAME}.bak"))
        temporary.replace(target)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
    console = get_console()
    console.print(f"wrote {target}", markup=False)
    if update_gitignore:
        console.print(_update_gitignore(directory), markup=False)
    else:
        console.print(
            "recommended: add .codekavach/ and codekavach-report/ to .gitignore "
            "(or run again with --update-gitignore)",
            markup=False,
        )
    for line in NEXT_STEPS:
        console.print(line, markup=False)


config_app.command("init")(init_command)


# --- config policy: show, sign, verify (E03-32) --------------------------------------------------

policy_app = typer.Typer(
    help=(
        "Inspect organisation policies and sign or verify their detached Ed25519 signatures. "
        "No key material is ever taken from an argument or printed."
    ),
    no_args_is_help=True,
)
config_app.add_typer(policy_app, name="policy")

_RULE_SECTIONS = ("privacy", "llm", "integrations", "project_config")


def _rule_summary(policy: "OrgPolicy") -> str:
    """``privacy.min_level=L3, llm.allowed_kinds=5, lock=2 keys`` from the rules that are set."""
    parts: list[str] = []
    for section in _RULE_SECTIONS:
        rules = getattr(policy, section).model_dump(mode="json")
        for name, value in rules.items():
            if value is None:
                continue
            if isinstance(value, list | dict):
                parts.append(f"{section}.{name}={len(value)}")
            else:
                shown = str(value).lower() if isinstance(value, bool) else str(value)
                parts.append(f"{section}.{name}={shown}")
    if policy.lock:
        parts.append(f"lock={len(policy.lock)} key{'s' if len(policy.lock) != 1 else ''}")
    return ", ".join(parts) or "none"


def _policy_document(loaded: "LoadedOrgPolicy") -> dict[str, Any]:
    policy = loaded.policy
    return {
        "organisation": policy.organisation,
        "path": str(loaded.path),
        "origin": loaded.origin,
        "sha256": loaded.sha256,
        "signature": loaded.signature,
        "enforcement": policy.enforcement,
        "issued": policy.issued.isoformat() if policy.issued else None,
        "expires": policy.expires.isoformat() if policy.expires else None,
        "rules": {
            **{section: getattr(policy, section).model_dump(mode="json")
               for section in _RULE_SECTIONS},
            "lock": dict(policy.lock),
        },
    }  # fmt: skip


@policy_app.command("show")
def policy_show(
    ctx: typer.Context,
    target: Annotated[
        Path | None, typer.Argument(help="Project directory; default: the current directory.")
    ] = None,
    output_format: Annotated[
        ListFormat, typer.Option("--format", help="Output format.")
    ] = ListFormat.text,
) -> None:
    """Show the organisation policies that apply here, with their signature state."""
    from codekavach.config.orgpolicy.discovery import discover_org_policies  # noqa: PLC0415
    from codekavach.config.orgpolicy.signature import find_public_key  # noqa: PLC0415
    from codekavach.config.paths import project_root_for, system_policy_paths  # noqa: PLC0415

    start = (target or Path.cwd()).resolve()
    policies = discover_org_policies(os.environ, project_root=project_root_for(start))
    documents = [_policy_document(loaded) for loaded in policies]
    if _json_wanted(ctx, output_format):
        _write_json(ctx, documents)
        return
    console = get_console()
    if not policies:
        console.print("no organisation policy is active", markup=False)
        return
    key = find_public_key(os.environ, [path.parent for path in system_policy_paths()])
    for index, (loaded, document) in enumerate(zip(policies, documents, strict=True)):
        if index:
            console.print("", markup=False)
        signature = document["signature"]
        if signature == "valid" and key is not None:
            signature = f"valid (key {key})"
        sha = document["sha256"]
        rows = [
            ("organisation", document["organisation"]),
            ("path", f"{document['path']}   ({document['origin']})"),
            ("sha256", f"{sha[:4]}...{sha[-2:]}"),
            ("signature", signature),
            ("enforcement", document["enforcement"]),
        ]
        if document["issued"]:
            rows.append(("issued", document["issued"]))
        if document["expires"]:
            rows.append(("expires", document["expires"]))
        rows.append(("rules", _rule_summary(loaded.policy)))
        for label, value in rows:
            console.print(f"{label:<14} {value}", markup=False, soft_wrap=True)


def _signing_key(path: Path) -> "Ed25519PrivateKey":
    """Load the private key, prompting for a passphrase (hidden) when it is encrypted."""
    from codekavach.config.orgpolicy.signature import load_private_key  # noqa: PLC0415

    try:
        return load_private_key(path, None)
    except OrgPolicyError as error:
        if "needs a passphrase" not in error.issues[0].message:
            raise
    if not sys.stdin.isatty():
        raise UsageError(
            "the signing key is encrypted and standard input is not a terminal, so the "
            "passphrase cannot be prompted for",
            code="prompt_unavailable",
            hint="sign on the policy owner's workstation, in a terminal",
        )
    passphrase = typer.prompt("Passphrase", hide_input=True)
    return load_private_key(path, passphrase.encode("utf-8"))


def _write_atomically(path: Path, text: str, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(text)
        Path(temporary).chmod(mode)
        Path(temporary).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()
        raise


def _validated_policy_bytes(policy: Path) -> bytes:
    from codekavach.config.orgpolicy.model import OrgPolicy  # noqa: PLC0415
    from codekavach.config.toml_source import (  # noqa: PLC0415
        parse_toml_bytes,
        read_bounded_bytes,
    )

    raw = read_bounded_bytes(policy)
    try:
        OrgPolicy.model_validate(parse_toml_bytes(raw, policy).data)
    except ValidationError:
        raise UsageError(
            "the file is not a valid organisation policy; refusing to sign it",
            code="invalid_policy",
            hint="check it with: codekavach config validate",
        ) from None
    return raw


@policy_app.command("sign")
def policy_sign(
    policy: Annotated[Path, typer.Argument(help="The policy file to sign.")],
    key: Annotated[Path, typer.Option("--key", help="Ed25519 private key, PEM PKCS#8 (mode 600).")],
    out: Annotated[
        Path | None, typer.Option("--out", help="Signature file; default: POLICY.sig.")
    ] = None,
) -> None:
    """Sign a policy file with an Ed25519 key and write the detached signature.

    Meant for the policy owner's workstation, not for pipelines: keep the private key offline.
    An encrypted key's passphrase is asked for with hidden input. Create a key pair with
    `openssl genpkey -algorithm ed25519 -out policy.key` and
    `openssl pkey -in policy.key -pubout -out policy.pub`.
    """
    from codekavach.config.orgpolicy.signature import (  # noqa: PLC0415
        sign_policy,
        signature_path,
    )

    raw = _validated_policy_bytes(policy)
    signing_key = _signing_key(key)
    destination = out or signature_path(policy)
    _write_atomically(destination, sign_policy(raw, signing_key) + "\n", 0o644)
    get_console().print(f"signature written to {destination}", markup=False)


@policy_app.command("verify")
def policy_verify(
    policy: Annotated[Path, typer.Argument(help="The policy file to verify.")],
    pubkey: Annotated[
        Path, typer.Option("--pubkey", help="Ed25519 public key, PEM SubjectPublicKeyInfo.")
    ],
    sig: Annotated[
        Path | None, typer.Option("--sig", help="Signature file; default: POLICY.sig.")
    ] = None,
) -> None:
    """Verify a policy's detached Ed25519 signature; exit 2 with code 054 when it fails."""
    from codekavach.config.orgpolicy.signature import (  # noqa: PLC0415
        MAX_SIGNATURE_BYTES,
        load_public_key,
        read_signature,
        signature_path,
        verify_policy,
    )
    from codekavach.config.toml_source import read_bounded_bytes  # noqa: PLC0415

    raw = read_bounded_bytes(policy)
    if sig is None or sig == signature_path(policy):
        text = read_signature(policy)
    else:
        data = sig.read_bytes()[: MAX_SIGNATURE_BYTES + 1]
        if len(data) > MAX_SIGNATURE_BYTES:
            raise UsageError("the signature file is too large", code="invalid_signature")
        text = data.decode("ascii", errors="replace")
    verify_policy(raw, text, load_public_key(pubkey))
    get_console().print("signature valid", markup=False)
