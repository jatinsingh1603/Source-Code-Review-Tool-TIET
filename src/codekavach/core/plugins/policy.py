"""Applying the ``[plugins]`` settings to discovered plugins, before anything is imported.

Owning epic: E04.

Loading a plugin imports its module, which runs code from an installed distribution. The policy is
therefore applied to the discovered ``PluginSpec`` records, which are read from distribution
metadata only, and a plugin that is not allowed is never loaded.

A spec is *allowed* when ``plugins.allow_distributions`` is empty or names its distribution
(compared after PEP 503 normalisation). The distribution ``codekavach`` is always allowed, since
the tool cannot run without it. A spec is *disabled* when it is not allowed, or when
``<kind>:<name>`` is listed in ``plugins.disable``; the entry names the plugin in every
distribution. The two stages that carry privacy (``privacy-prepare`` and ``restore``) cannot be
listed: settings validation refuses them (E03-03), so this module may assume validated input.

This is a supply-chain control for installed code, not a sandbox: an allowed plugin runs with the
rights of the process. Both keys are restricted settings, so a scanned repository cannot change
them through its own ``codekavach.toml`` (E03-25).
"""

from collections.abc import Sequence
from typing import Literal

from codekavach.config.models.plugins import PluginsSettings, normalise_distribution
from codekavach.core.log import get_logger
from codekavach.core.plugins.discovery import CORE_DIST, PluginSpec, kind_of

Reason = Literal["disabled", "not_allowed"]

_log = get_logger("codekavach.plugins")


def disabled_reason(
    spec: PluginSpec, allowed_distributions: frozenset[str], disabled: frozenset[str]
) -> Reason | None:
    """Why ``spec`` may not load, or None when it may; the arguments are already normalised.

    An empty ``allowed_distributions`` allows every distribution.
    """
    if f"{kind_of(spec.group)}:{spec.name}" in disabled:
        return "disabled"
    dist = normalise_distribution(spec.dist_name)
    if allowed_distributions and dist not in allowed_distributions:
        return "not_allowed"
    return None


def apply_policy(
    specs: Sequence[PluginSpec], settings: PluginsSettings
) -> tuple[list[PluginSpec], list[PluginSpec]]:
    """Split ``specs`` into the plugins that may load and those that may not, keeping the order."""
    allowed_distributions: frozenset[str] = frozenset()
    if settings.allow_distributions:
        names = (*settings.allow_distributions, CORE_DIST)
        allowed_distributions = frozenset(normalise_distribution(name) for name in names)
    disabled_entries = frozenset(settings.disable)
    allowed: list[PluginSpec] = []
    disabled: list[PluginSpec] = []
    for spec in specs:
        reason = disabled_reason(spec, allowed_distributions, disabled_entries)
        if reason is None:
            allowed.append(spec)
            continue
        disabled.append(spec)
        _log.debug(
            "plugin_disabled",
            group=spec.group,
            plugin=spec.name,
            dist=spec.dist_name,
            reason=reason,
        )
    return allowed, disabled
