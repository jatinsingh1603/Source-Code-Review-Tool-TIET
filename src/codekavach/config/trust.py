"""Restricted keys in untrusted project configuration (ADR decision D6, E03-25).

Owning epic: E03.

``codekavach.toml`` travels with the repository, so in a pull-request scan or an audit of
third-party code it is written by someone other than the operator. Unless the operator trusts
the project, its configuration (including every ``[profiles.*]`` table it defines, selected or
not) may not set endpoints, executables, credentials, provider definitions, plugin lists or
integration targets, and its path keys must stay inside the project. Violations are reported
together as code 040 without their values (CWE-532, CWE-117): an attacker-chosen URL can be
designed to look legitimate in a log.

Trust for one run comes from ``--trust-project-config`` or ``CODEKAVACH_TRUST_PROJECT_CONFIG``;
a project file given explicitly from outside the project root is the operator's own file. A CI
pipeline that scans its own default branch may set ``CODEKAVACH_TRUST_PROJECT_CONFIG=1``; a
pipeline that scans pull requests from forks must not.

Consent for remote egress is deliberately not a setting (E05-13), so no file can grant it.
"""

import contextlib
import hmac
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Any, Literal

from codekavach.config.constants import TRUST_STORE_FILE_NAME
from codekavach.config.errors import DEFAULT_SEVERITY, ConfigError, ConfigErrorCode, ConfigIssue
from codekavach.config.introspect import flatten_leaves, keys_with_marker
from codekavach.config.merge import deep_merge
from codekavach.config.models.base import split_csv
from codekavach.config.models.root import Settings
from codekavach.config.paths import user_config_dir
from codekavach.config.provenance import Layer
from codekavach.config.toml_source import locate_key
from codekavach.core.models import PrivacyLevel

TRUST_ENV = "CODEKAVACH_TRUST_PROJECT_CONFIG"
_TRUE = frozenset({"1", "true"})

# The documented list (glob syntax: ``*`` one segment, ``**`` one or more segments).
RESTRICTED_PATTERNS: tuple[str, ...] = (
    "llm.providers.**",
    "engines.options.*.executable",
    "engines.options.*.args",
    "engines.options.*.env_passthrough",
    "reporting.template_dir",
    "integrations.**",
    "privacy.vault.**",
    "privacy.public_allowlist_extra",
    "plugins.**",
)
CONTAINED_PATH_KEYS: tuple[str, ...] = (
    "project.state_dir",
    "reporting.output_dir",
    "reporting.logo",
    "privacy.domain_terms_file",
    "engines.rule_paths[*]",
)

TrustReason = Literal["flag", "env", "external-config", "store", "org-policy", "untrusted"]
POLICY_FORBIDS_TRUST_HINT = (
    "the organisation policy forbids trusting project files (project_config.allow_trust = "
    "false); move the setting to your user configuration or remove it from the project file"
)


def _segment_match(pattern: list[str], parts: list[str]) -> bool:
    if not pattern:
        return not parts
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_segment_match(rest, parts[size:]) for size in range(1, len(parts) + 1))
    return bool(parts) and head in ("*", parts[0]) and _segment_match(rest, parts[1:])


def _matches(pattern: str, key: str) -> bool:
    return _segment_match(pattern.split("."), key.split("."))


@cache
def restricted_patterns() -> tuple[str, ...]:
    """The documented patterns united with every key marked ``x-ck-restricted``."""
    marked = sorted(keys_with_marker(Settings, "restricted"))
    extra = [key for key in marked if not any(_matches(p, key) for p in RESTRICTED_PATTERNS)]
    return (*RESTRICTED_PATTERNS, *extra)


def is_restricted(dotted_key: str) -> bool:
    """True when an untrusted project configuration may not set ``dotted_key``."""
    key = re.sub(r"\[\d+\]", "", dotted_key)
    return any(_matches(pattern, key) for pattern in restricted_patterns())


def is_project_trusted(
    *,
    flag: bool,
    env: Mapping[str, str],
    loaded_external: bool,
    store: "TrustStore | None" = None,
    root: Path | None = None,
    sha256: str | None = None,
    policy_forbids: bool = False,
) -> tuple[bool, TrustReason]:
    """Whether the project configuration is trusted for this run, and why.

    A store grant counts only for the exact bytes of the configuration file (``sha256`` of the
    same read that the loader parsed, CWE-367). An organisation policy with
    ``project_config.allow_trust = false`` overrides every source (E03-29).
    """
    if policy_forbids:
        return False, "org-policy"
    if flag:
        return True, "flag"
    if env.get(TRUST_ENV, "").strip().lower() in _TRUE:
        return True, "env"
    if loaded_external:
        return True, "external-config"
    if store is not None and root is not None and sha256 and store.is_trusted(root, sha256):
        return True, "store"
    return False, "untrusted"


def _hint(project_root: Path, user_config: Path | None) -> str:
    target = str(user_config) if user_config is not None else "your user configuration"
    return (
        "endpoints, executables, credentials, plugin lists and integration targets are accepted "
        "only from\nyour user configuration or from a trusted project. Review the file, then "
        "either move the\nsetting to "
        f"{target}, or trust this project:\n"
        f"    codekavach config trust {project_root}          "
        "(persistent, re-asked when the file changes)\n"
        "    --trust-project-config                 (this run only)"
    )


def _escapes(value: str, project_root: Path) -> bool:
    if value.startswith(("~", "/", "\\")) or any(
        pure(value).is_absolute() for pure in (PurePosixPath, PureWindowsPath)
    ):
        return True
    if PureWindowsPath(value).drive:
        return True
    if ".." in re.split(r"[\\/]", value):
        return True
    root = project_root.resolve(strict=False)
    return not (root / value).resolve(strict=False).is_relative_to(root)


def _roots(data: Mapping[str, Any]) -> Iterator[tuple[str, Mapping[str, Any]]]:
    """The layer itself, then every profile table it defines, with the key prefix to report."""
    yield "", {key: value for key, value in data.items() if key != "profiles"}
    profiles = data.get("profiles")
    if isinstance(profiles, Mapping):
        for name, table in profiles.items():
            if isinstance(table, Mapping):
                yield f"profiles.{name}.", table


def _contained_values(data: Mapping[str, Any]) -> Iterator[tuple[str, Any]]:
    for key in CONTAINED_PATH_KEYS:
        base, _, rest = key.partition("[")
        node: Any = data
        for part in base.split("."):
            node = node.get(part) if isinstance(node, Mapping) else None
        if node is None:
            continue
        if rest and isinstance(node, list):
            for index, item in enumerate(node):
                yield f"{base}[{index}]", item
        else:
            yield base, node


def check_restricted(
    layer: Layer, *, project_root: Path, user_config: Path | None = None
) -> list[ConfigIssue]:
    """One code-040 issue per restricted key or escaping path in the raw project layer."""
    issues: list[ConfigIssue] = []
    hint = _hint(project_root, user_config)

    def add(key: str, message: str) -> None:
        issues.append(
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_040,
                severity=DEFAULT_SEVERITY[ConfigErrorCode.CK_CFG_040],
                message=message,
                key=key,
                source=layer.source,
                line=locate_key(layer.text, key) if layer.text is not None else None,
                hint=hint,
            )
        )

    for prefix, data in _roots(layer.data):
        for key in flatten_leaves(data):
            if is_restricted(key):
                add(
                    f"{prefix}{key}",
                    f"'{prefix}{key}' may not be set by an untrusted project configuration",
                )
        for key, value in _contained_values(data):
            if isinstance(value, str) and _escapes(value, project_root):
                add(f"{prefix}{key}", f"'{prefix}{key}': path escapes the project")
    return issues


# --- tighten-only keys (E03-26) ----------------------------------------------------------------

Comparator = Callable[[Any, Any], bool]
PROTECTED_STAGES: tuple[str, ...] = ("privacy-prepare", "restore", "aggregate", "rate")
_DROPPED_RULE = "drops a stricter path rule from the user configuration"


def _level(value: Any) -> PrivacyLevel | None:
    try:
        return PrivacyLevel(str(value).upper())
    except ValueError:
        return None


def _level_looser(candidate: Any, baseline: Any) -> bool:
    new, old = _level(candidate), _level(baseline)
    return new is not None and old is not None and not new.at_least(old)


def _switched_on(candidate: Any, baseline: Any) -> bool:
    return candidate is True and baseline is False


def _skips_protected(candidate: Any, baseline: Any) -> bool:
    new = set(split_csv(candidate)) if isinstance(candidate, list | str) else set()
    old = set(split_csv(baseline)) if isinstance(baseline, list | str) else set()
    return any(stage in new and stage not in old for stage in PROTECTED_STAGES)


TIGHTEN_ONLY: Mapping[str, Comparator] = MappingProxyType(
    {
        "privacy.level": _level_looser,
        "privacy.min_level": _level_looser,
        "privacy.provider_tier_levels.*": _level_looser,
        "llm.allow_remote": _switched_on,
        "llm.enabled": _switched_on,
        "scan.follow_symlinks": _switched_on,
        "scan.skip_stages": _skips_protected,
    }
)


def _get(data: Mapping[str, Any], key: str) -> Any:
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


_MISSING = object()


def _concrete(data: Mapping[str, Any], template: str) -> Iterator[str]:
    """Concrete keys of ``data`` matching a template with at most one trailing ``*``."""
    if not template.endswith(".*"):
        if _get(data, template) is not _MISSING:
            yield template
        return
    parent = template[:-2]
    table = _get(data, parent)
    if isinstance(table, Mapping):
        yield from (f"{parent}.{name}" for name in table)


def _show(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(str(item) for item in value) + "]"
    return str(value)


def _path_rule_issues(
    candidate: Mapping[str, Any], baseline: Mapping[str, Any]
) -> Iterator[tuple[str, str]]:
    """``(key, message)`` for path rules looser than the baseline level or dropping user rules."""
    rules = _get(candidate, "privacy.paths")
    if not isinstance(rules, list):
        return
    base_level = _get(baseline, "privacy.level")
    for index, rule in enumerate(rules):
        if isinstance(rule, Mapping) and _level_looser(rule.get("level"), base_level):
            yield (
                f"privacy.paths[{index}].level",
                f"privacy.paths[{index}].level {_show(rule['level'])} is weaker than the "
                f"baseline privacy.level {_show(base_level)}",
            )
    project_level = _get(candidate, "privacy.level")
    if project_level is _MISSING:
        project_level = base_level
    by_pattern: dict[Any, Mapping[str, Any]] = {}
    for rule in rules:
        if isinstance(rule, Mapping):
            by_pattern[rule.get("pattern")] = rule  # later rules win
    base_rules = _get(baseline, "privacy.paths")
    for rule in base_rules if isinstance(base_rules, list) else []:
        mine = by_pattern.get(rule.get("pattern"))
        if rule.get("never_send"):
            dropped = mine is None or not mine.get("never_send")
        else:
            if mine is not None and mine.get("never_send"):
                continue
            effective = mine.get("level") if mine is not None and mine.get("level") else None
            dropped = _level_looser(effective or project_level, rule.get("level"))
        if dropped:
            yield "privacy.paths", f"privacy.paths {_DROPPED_RULE}"


def check_tighten_only(
    candidate: Mapping[str, Any],
    baseline: Mapping[str, Any],
    *,
    source: str,
    text: str | None,
    prefix: str = "",
    subject: str = "",
    line: int | None = None,
    baseline_origin: Callable[[str], str] | None = None,
    hint: str | None = None,
) -> list[ConfigIssue]:
    """One code-041 issue per tighten-only key that ``candidate`` sets looser than ``baseline``.

    ``prefix`` is prepended to reported keys (``profiles.x.`` for a profile table); ``subject``
    replaces the default message subject (for a project-selected profile), and ``line`` then
    replaces the per-key line. Levels, booleans and stage names come from closed sets and are
    printed; nothing else is.
    """
    found: list[tuple[str, str]] = []
    for template, looser in TIGHTEN_ONLY.items():
        for key in _concrete(candidate, template):
            new, old = _get(candidate, key), _get(baseline, key)
            if old is not _MISSING and looser(new, old):
                verb = "add a skipped stage to" if key == "scan.skip_stages" else "lower"
                found.append((key, f"would {verb} {key} from {_show(old)} to {_show(new)}"))
    found.extend((key, message) for key, message in _path_rule_issues(candidate, baseline))
    issues = []
    for key, message in found:
        origin = f"; baseline from {baseline_origin(key)}" if baseline_origin else ""
        who = subject or "an untrusted project configuration"
        text_message = (
            f"{who} {message}{origin}"
            if message.startswith("would")
            else f"{message} ({who}){origin}"
        )
        issues.append(
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_041,
                severity=DEFAULT_SEVERITY[ConfigErrorCode.CK_CFG_041],
                message=text_message,
                key=f"{prefix}{key}",
                source=source,
                line=line
                if line is not None
                else (locate_key(text, f"{prefix}{key}") if text is not None else None),
                hint=hint
                or "move the stricter value into your user configuration only if you "
                "want it everywhere; otherwise remove the looser value, or trust this project.",
            )
        )
    return issues


# --- violations of one project file (shared by the loader and ``config trust``) --------------


def baseline_settings(user: Layer | None) -> dict[str, Any]:
    """Everything below the project layer: the defaults merged with the user layer."""
    baseline: dict[str, Any] = Settings().model_dump(mode="json")
    if user is not None:
        data = {k: v for k, v in user.data.items() if k not in {"profile", "profiles"}}
        baseline = deep_merge(baseline, data, union_keys=keys_with_marker(Settings, "union"))
    return baseline


def baseline_origin(user: Layer | None) -> Callable[[str], str]:
    """Where the baseline value of a key comes from: the user file and line, or the defaults."""
    flat = flatten_leaves(user.data) if user is not None else {}

    def origin(key: str) -> str:
        base = key.split("[", maxsplit=1)[0]
        if user is None or base not in flat:
            return "the built-in defaults"
        line = locate_key(user.text, base) if user.text is not None else None
        return user.source if line is None else f"{user.source}:{line}"

    return origin


def project_violations(
    project: Layer, *, project_root: Path, user: Layer | None, user_config: Path | None = None
) -> list[ConfigIssue]:
    """Codes 040 and 041 for the raw project layer and every profile table it defines."""
    issues = check_restricted(project, project_root=project_root, user_config=user_config)
    baseline = baseline_settings(user)
    common: dict[str, Any] = {"source": project.source, "baseline_origin": baseline_origin(user)}
    data = {k: v for k, v in project.data.items() if k not in {"profile", "profiles"}}
    issues += check_tighten_only(data, baseline, text=project.text, **common)
    profiles = project.data.get("profiles")
    for name, table in profiles.items() if isinstance(profiles, Mapping) else ():
        if isinstance(table, Mapping):
            issues += check_tighten_only(
                table, baseline, text=project.text, prefix=f"profiles.{name}.", **common
            )
    return issues


# --- persistent trust store (E03-27) -----------------------------------------------------------

STORE_VERSION = 1
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class TrustEntry:
    """One trusted project: its root, the SHA-256 of its configuration file and when."""

    root: str
    sha256: str
    trusted_at: str


def store_path(env: Mapping[str, str]) -> Path:
    """``<user_config_dir>/trusted-projects.json``."""
    return user_config_dir(env) / TRUST_STORE_FILE_NAME


def _store_key(root: Path) -> str:
    return os.path.normcase(str(root.resolve()))


def _corrupt(path: Path, reason: str) -> ConfigError:
    return ConfigError.single(
        ConfigErrorCode.CK_CFG_042,
        f"trust store is unreadable or corrupt: {reason}",
        source=str(path),
        hint="delete the file and trust your projects again with codekavach config trust",
    )


def _parse_store(path: Path, raw: bytes) -> dict[str, dict[str, str]]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _corrupt(path, "not valid JSON") from None
    if not isinstance(document, dict) or document.get("version") != STORE_VERSION:
        raise _corrupt(path, f"expected an object with version {STORE_VERSION}")
    projects = document.get("projects")
    if not isinstance(projects, dict):
        raise _corrupt(path, "projects must be an object")
    parsed: dict[str, dict[str, str]] = {}
    for root, entry in projects.items():
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("sha256"), str)
            or not _SHA256.fullmatch(entry["sha256"])
            or not isinstance(entry.get("trusted_at", ""), str)
        ):
            raise _corrupt(path, "an entry is malformed")
        parsed[str(root)] = {"sha256": entry["sha256"], "trusted_at": entry.get("trusted_at", "")}
    return parsed


class TrustStore:
    """Projects the user trusts, each bound to the exact bytes of its configuration file.

    Stored as JSON at ``<user_config_dir>/trusted-projects.json`` (directory ``0o700``, file
    ``0o600``), written atomically; holds paths and hashes only. Any edit of a trusted file,
    whitespace included, changes its hash and lapses the grant (direnv-style).
    """

    def __init__(self, path: Path, projects: Mapping[str, Mapping[str, str]] | None = None) -> None:
        self.path = path
        self._projects: dict[str, dict[str, str]] = {
            root: dict(entry) for root, entry in (projects or {}).items()
        }

    @classmethod
    def load(cls, path: Path) -> "TrustStore":
        """Read the store; a missing file is an empty store.

        Raises:
            ConfigError: CK-CFG-042 when the file cannot be read or is not a valid store.
        """
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return cls(path)
        except OSError:
            raise _corrupt(path, "the file cannot be read") from None
        return cls(path, _parse_store(path, raw))

    def is_trusted(self, root: Path, sha256: str) -> bool:
        """True when ``root`` is trusted for exactly this configuration content."""
        entry = self._projects.get(_store_key(root))
        return entry is not None and hmac.compare_digest(entry["sha256"], sha256)

    def grant(self, root: Path, sha256: str) -> None:
        """Trust ``root`` for this content and save."""
        now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self._projects[_store_key(root)] = {"sha256": sha256, "trusted_at": now}
        self.save()

    def revoke(self, root: Path) -> bool:
        """Forget ``root`` and save; False when it was not trusted."""
        if self._projects.pop(_store_key(root), None) is None:
            return False
        self.save()
        return True

    def entries(self) -> list[TrustEntry]:
        """Every trusted project, sorted by root."""
        return [
            TrustEntry(root, entry["sha256"], entry.get("trusted_at", ""))
            for root, entry in sorted(self._projects.items())
        ]

    def save(self) -> None:
        """Write atomically: a temporary file in the same directory, then ``os.replace``."""
        directory = self.path.parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        document = {"version": STORE_VERSION, "projects": self._projects}
        data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
        descriptor, name = tempfile.mkstemp(dir=directory, prefix=".trusted-", suffix=".tmp")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o600)
            temporary.replace(self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise
