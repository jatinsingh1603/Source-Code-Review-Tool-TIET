"""Enforcing an organisation policy on the merged settings (ADR decisions D2, D7, E03-29).

Owning epic: E03.

Enforcement works on ``settings.model_dump(mode="json")`` so that the loader can re-validate the
result with every section validator. Two rules only ever tighten and are applied, never reported:
``privacy.min_level`` raises the floor and ``privacy.never_send`` adds globs
(``apply_additions``). Every other rule is a check (``check_policy``): a configuration that
breaks it is a violation, reported with the origin of the offending value. Levels, booleans,
provider ids, kinds and host names are printed; other free text is not (CWE-532).
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from codekavach.config.models.llm import ProviderKind, ProviderSettings, is_loopback_host
from codekavach.config.orgpolicy.model import OrgPolicy
from codekavach.core.models import PrivacyLevel, TrustTier

ALWAYS_ALLOWED_KINDS = frozenset({ProviderKind.MOCK.value, ProviderKind.REPLAY.value})
_MISSING = object()


@dataclass(frozen=True, slots=True)
class Violation:
    """One way in which settings break a policy rule."""

    key: str
    rule: str
    message: str
    clampable: bool
    clamp_to: Any = None


def _get(data: Mapping[str, Any], key: str) -> Any:
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _level(value: Any) -> PrivacyLevel | None:
    try:
        return PrivacyLevel(str(value).upper())
    except ValueError:
        return None


def locked_keys_of(policy: OrgPolicy) -> set[str]:
    """Keys that no layer can change while ``policy`` applies."""
    keys = set(policy.lock)
    if policy.privacy.min_level is not None:
        keys.add("privacy.min_level")
    if policy.llm.allow_remote is not None:
        keys.add("llm.allow_remote")
    if policy.integrations.allow_github is not None:
        keys.add("integrations.github.enabled")
    return keys


def apply_additions(
    settings_data: Mapping[str, Any], policy: OrgPolicy
) -> tuple[dict[str, Any], set[str]]:
    """Raise the floor and add never-send globs; returns new data and the keys that changed."""
    privacy = dict(settings_data.get("privacy", {}))
    changed: set[str] = set()
    floor = policy.privacy.min_level
    current = _level(privacy.get("min_level"))
    if floor is not None and (current is None or not current.at_least(floor)):
        privacy["min_level"] = floor.value
        changed.add("privacy.min_level")
    globs = policy.privacy.never_send or []
    existing = list(privacy.get("never_send", []))
    missing = [glob for glob in globs if glob not in existing]
    if missing:
        privacy["never_send"] = [*existing, *missing]
        changed.add("privacy.never_send")
    if not changed:
        return dict(settings_data), changed
    return {**settings_data, "privacy": privacy}, changed


def _level_rules(data: Mapping[str, Any], policy: OrgPolicy, name: str) -> list[Violation]:
    found: list[Violation] = []
    floor = policy.privacy.min_level
    if floor is not None:
        level = _level(_get(data, "privacy.level"))
        if level is not None and not level.at_least(floor):
            found.append(
                Violation(
                    "privacy.level",
                    "privacy.min_level",
                    f"organisation policy '{name}' requires privacy.level to be at least "
                    f"{floor} (configured: {level})",
                    clampable=True,
                    clamp_to=floor.value,
                )
            )
        paths = _get(data, "privacy.paths")
        for index, rule in enumerate(paths if isinstance(paths, list) else []):
            rule_level = _level(rule.get("level")) if isinstance(rule, Mapping) else None
            if rule_level is not None and not rule_level.at_least(floor):
                found.append(
                    Violation(
                        f"privacy.paths[{index}].level",
                        "privacy.min_level",
                        f"organisation policy '{name}' requires privacy.paths[{index}].level to "
                        f"be at least {floor} (configured: {rule_level})",
                        clampable=True,
                        clamp_to=floor.value,
                    )
                )
    for tier, minimum in (policy.privacy.min_level_by_tier or {}).items():
        key = f"privacy.provider_tier_levels.{TrustTier(tier).value}"
        configured = _level(_get(data, key))
        if configured is None or not configured.at_least(minimum):
            found.append(
                Violation(
                    key,
                    "privacy.min_level_by_tier",
                    f"organisation policy '{name}' requires {key} to be at least {minimum} "
                    f"(configured: {configured or 'unset'})",
                    clampable=True,
                    clamp_to=minimum.value,
                )
            )
    extra = _get(data, "privacy.public_allowlist_extra")
    if policy.privacy.forbid_allowlist_extra and isinstance(extra, list) and extra:
        found.append(
            Violation(
                "privacy.public_allowlist_extra",
                "privacy.forbid_allowlist_extra",
                f"organisation policy '{name}' forbids privacy.public_allowlist_extra "
                f"({len(extra)} entries configured)",
                clampable=True,
                clamp_to=[],
            )
        )
    return found


def _enabled_providers(data: Mapping[str, Any]) -> list[tuple[str, ProviderSettings]]:
    providers = _get(data, "llm.providers")
    result = []
    for provider_id, raw in providers.items() if isinstance(providers, Mapping) else ():
        provider = ProviderSettings.model_validate(raw)
        if provider.enabled:
            result.append((str(provider_id), provider))
    return result


def _llm_rules(data: Mapping[str, Any], policy: OrgPolicy, name: str) -> list[Violation]:
    rules = policy.llm
    found: list[Violation] = []
    if rules.allow_remote is False and _get(data, "llm.allow_remote") is True:
        found.append(
            Violation(
                "llm.allow_remote",
                "llm.allow_remote",
                f"organisation policy '{name}' forbids remote providers (llm.allow_remote: true)",
                clampable=True,
                clamp_to=False,
            )
        )
    allowed_hosts = {host.lower() for host in rules.allowed_base_url_hosts or []}
    for provider_id, provider in _enabled_providers(data):
        key = f"llm.providers.{provider_id}"
        kind = str(provider.kind)
        if kind in ALWAYS_ALLOWED_KINDS:
            continue
        if rules.allowed_kinds is not None and kind not in {str(k) for k in rules.allowed_kinds}:
            found.append(
                Violation(
                    f"{key}.kind",
                    "llm.allowed_kinds",
                    f"organisation policy '{name}' does not allow provider kind {kind} "
                    f"({provider_id})",
                    clampable=True,
                    clamp_to=False,
                )
            )
        if rules.allowed_providers and provider_id not in rules.allowed_providers:
            found.append(
                Violation(
                    key,
                    "llm.allowed_providers",
                    f"organisation policy '{name}' does not allow provider '{provider_id}'",
                    clampable=True,
                    clamp_to=False,
                )
            )
        if rules.allowed_base_url_hosts is not None and provider.is_remote:
            host = (provider.host or "").lower()
            if provider.base_url is None:
                found.append(
                    Violation(
                        f"{key}.base_url",
                        "llm.allowed_base_url_hosts",
                        f"organisation policy '{name}' restricts provider hosts; provider "
                        f"'{provider_id}': set base_url explicitly so that the host can be "
                        "checked",
                        clampable=True,
                        clamp_to=False,
                    )
                )
            elif host not in allowed_hosts and not is_loopback_host(host):
                found.append(
                    Violation(
                        f"{key}.base_url",
                        "llm.allowed_base_url_hosts",
                        f"organisation policy '{name}' does not allow host {host} "
                        f"(provider '{provider_id}')",
                        clampable=True,
                        clamp_to=False,
                    )
                )
    return found


def _integration_rules(data: Mapping[str, Any], policy: OrgPolicy, name: str) -> list[Violation]:
    rules = policy.integrations
    found: list[Violation] = []
    enabled = _get(data, "integrations.github.enabled") is True
    if rules.allow_github is False and enabled:
        found.append(
            Violation(
                "integrations.github.enabled",
                "integrations.allow_github",
                f"organisation policy '{name}' forbids the GitHub integration",
                clampable=True,
                clamp_to=False,
            )
        )
    if rules.allowed_github_api_hosts is not None and enabled:
        api_url = _get(data, "integrations.github.api_url")
        host = (urlsplit(str(api_url)).hostname or "").lower() if api_url is not _MISSING else ""
        if host not in {h.lower() for h in rules.allowed_github_api_hosts}:
            found.append(
                Violation(
                    "integrations.github.api_url",
                    "integrations.allowed_github_api_hosts",
                    f"organisation policy '{name}' does not allow GitHub API host {host}",
                    clampable=False,
                )
            )
    return found


def _lock_rules(data: Mapping[str, Any], policy: OrgPolicy, name: str) -> list[Violation]:
    found: list[Violation] = []
    for key, locked in policy.lock.items():
        value = _get(data, key)
        if value is _MISSING or value != locked:
            found.append(
                Violation(
                    key,
                    "lock",
                    f"organisation policy '{name}' locks {key}; the configured value differs",
                    clampable=True,
                    clamp_to=locked,
                )
            )
    return found


def check_policy(settings_data: Mapping[str, Any], policy: OrgPolicy) -> list[Violation]:
    """Every violation of ``policy`` by ``settings_data`` (a dumped ``Settings``), in rule order."""
    name = policy.organisation
    return [
        *_level_rules(settings_data, policy, name),
        *_llm_rules(settings_data, policy, name),
        *_integration_rules(settings_data, policy, name),
        *_lock_rules(settings_data, policy, name),
    ]
