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

import re
from collections.abc import Callable, Iterator, Mapping
from functools import cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Any, Literal

from codekavach.config.errors import DEFAULT_SEVERITY, ConfigErrorCode, ConfigIssue
from codekavach.config.introspect import flatten_leaves, keys_with_marker
from codekavach.config.models.base import split_csv
from codekavach.config.models.root import Settings
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

TrustReason = Literal["flag", "env", "external-config", "untrusted"]


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
    *, flag: bool, env: Mapping[str, str], loaded_external: bool
) -> tuple[bool, TrustReason]:
    """Whether the project configuration is trusted for this run, and why."""
    if flag:
        return True, "flag"
    if env.get(TRUST_ENV, "").strip().lower() in _TRUE:
        return True, "env"
    if loaded_external:
        return True, "external-config"
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
