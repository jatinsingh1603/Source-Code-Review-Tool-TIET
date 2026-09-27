"""The CLI override layer: which settings key each flag sets, and ``--set key=value``.

Owning epic: E03.

CLI flags are the top layer of the precedence chain (ADR D2). The flags and their help text belong
to E05; this module fixes once, next to the settings models, which dotted keys they set, so the
two epics cannot drift apart. ``--offline`` sets ``llm.allow_remote = false`` and disables the
GitHub and MCP integrations in one step, and leaves ``privacy.level`` to the configured policy.
Flags can lower ``privacy.level`` only down to ``privacy.min_level`` and the organisation floor,
which the loader enforces; this layer adds no bypass. Error messages name keys, never values.

Arrays replace lower layers (ADR D3); union-merged keys such as ``privacy.never_send`` still only
add. The integrations section (E03-09) is not part of every build yet: ``--offline`` disables the
integration keys that exist and has nothing to disable otherwise.
"""

import difflib
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from codekavach.config.errors import ConfigError, ConfigErrorCode
from codekavach.config.introspect import iter_fields, resolve_field
from codekavach.config.models.root import Settings
from codekavach.config.provenance import Layer


@dataclass(frozen=True, slots=True)
class Flag:
    """One row of the flag table: the flag spelling and the keys it sets.

    A boolean flag (``fixed`` given) sets every key to ``fixed`` when true and nothing when false.
    """

    flag: str
    keys: tuple[str, ...]
    fixed: Any = None
    boolean: bool = False
    optional_keys: frozenset[str] = frozenset()


FLAG_TO_KEY: Mapping[str, Flag] = MappingProxyType(
    {
        "privacy_level": Flag("--privacy-level", ("privacy.level",)),
        "provider": Flag("--provider", ("llm.default_provider",)),
        "model": Flag("--model", ("llm.model",)),
        "offline": Flag(
            "--offline",
            ("llm.allow_remote", "integrations.github.enabled", "integrations.mcp.enabled"),
            fixed=False,
            boolean=True,
            optional_keys=frozenset({"integrations.github.enabled", "integrations.mcp.enabled"}),
        ),
        "no_llm": Flag("--no-llm", ("llm.enabled",), fixed=False, boolean=True),
        "fail_on": Flag("--fail-on", ("scan.fail_on",)),
        "include": Flag("--include", ("scan.include",)),
        "exclude": Flag("--exclude", ("scan.exclude",)),
        "engine": Flag("--engine", ("engines.enabled",)),
        "skip_engine": Flag("--skip-engine", ("engines.disabled",)),
        "rules": Flag("--rules", ("engines.rule_paths",)),
        "formats": Flag("--format", ("reporting.formats",)),
        "output_dir": Flag("--output-dir", ("reporting.output_dir",)),
        "jobs": Flag("--jobs", ("scan.jobs",)),
        "log_level": Flag("--log-level", ("logging.level",)),
        "log_format": Flag("--log-format", ("logging.format",)),
    }
)


@dataclass(frozen=True, slots=True)
class CliOverrides:
    """Nested override data and, per dotted key, the flag that set it."""

    data: Mapping[str, Any] = field(default_factory=dict)
    key_sources: Mapping[str, str] = field(default_factory=dict)


def _error(message: str, *, key: str | None = None, hint: str | None = None) -> ConfigError:
    return ConfigError.single(ConfigErrorCode.CK_CFG_061, message, key=key, hint=hint)


def _set(data: dict[str, Any], key: str, value: Any) -> None:
    parts = key.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for name, value in data.items():
        key = f"{prefix}.{name}" if prefix else name
        if isinstance(value, Mapping) and value:
            flat.update(_flatten(value, key))
        else:
            flat[key] = value
    return flat


def _known(key: str) -> bool:
    return resolve_field(Settings, key) is not None


def overrides_from_flags(**flags: Any) -> CliOverrides:
    """Overrides for the given flag values (keyword names from ``FLAG_TO_KEY``).

    ``None``, ``False`` for boolean flags and empty sequences are ignored.

    Raises:
        TypeError: an unknown keyword (a programming error in the CLI).
        ConfigError: CK-CFG-061 when a flag's key is not part of this build.
    """
    unknown = sorted(set(flags) - FLAG_TO_KEY.keys())
    if unknown:
        raise TypeError(f"unknown flag keyword(s): {', '.join(unknown)}")
    data: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for name in sorted(flags):
        value = flags[name]
        row = FLAG_TO_KEY[name]
        if value is None or (row.boolean and not value):
            continue
        if isinstance(value, (list, tuple)):
            if not value:
                continue
            value = list(value)
        for key in row.keys:
            if not _known(key):
                if key in row.optional_keys:
                    continue
                raise _error(f"{row.flag} is not available in this build", key=key)
            _set(data, key, row.fixed if row.boolean else value)
            sources[key] = row.flag
    return CliOverrides(data=data, key_sources=sources)


def _closest(key: str) -> str | None:
    candidates = [ref.key for ref in iter_fields(Settings)]
    match = difflib.get_close_matches(key, candidates, n=1)
    return f"did you mean {match[0]}?" if match else None


def _value(text: str) -> Any:
    try:
        return tomllib.loads(f"v = {text}")["v"]
    except tomllib.TOMLDecodeError:
        return text


def parse_set_options(items: Sequence[str]) -> CliOverrides:
    """Overrides from ``--set key=value`` items; the value is TOML, or a bare string.

    Raises:
        ConfigError: CK-CFG-061 for a missing ``=``, an empty or unknown key, or a repeated key.
    """
    data: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for item in items:
        key, separator, text = item.partition("=")
        key = key.strip()
        if not separator:
            raise _error("--set expects KEY=VALUE")
        if not key:
            raise _error("--set has an empty key")
        if not _known(key):
            raise _error("--set names an unknown key", key=key, hint=_closest(key))
        if key in sources:
            raise _error("--set gives the same key twice", key=key)
        _set(data, key, _value(text.strip()))
        sources[key] = f"--set {key}"
    return CliOverrides(data=data, key_sources=sources)


def combine(*parts: CliOverrides) -> CliOverrides:
    """Merge override parts; a key set by two parts is an error (CK-CFG-061)."""
    data: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for part in parts:
        for key, value in _flatten(part.data).items():
            if key in sources:
                raise _error("the same key is set by more than one flag", key=key)
            _set(data, key, value)
            sources[key] = part.key_sources.get(key, "cli")
    return CliOverrides(data=data, key_sources=sources)


def cli_layer(overrides: CliOverrides | Mapping[str, Any]) -> Layer:
    """The ``cli`` layer; a plain mapping gets the source ``cli`` for every key."""
    if not isinstance(overrides, CliOverrides):
        overrides = CliOverrides(data=dict(overrides))
    return Layer(
        name="cli",
        source="cli",
        data=overrides.data,
        key_sources=MappingProxyType(dict(overrides.key_sources)),
    )
