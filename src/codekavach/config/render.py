"""Rendering the effective configuration as TOML or JSON, masked, with origins (E03-34).

Owning epic: E03.

Everything printed goes through ``mask_settings`` or ``mask_layer_data`` (E03-20): output of
``codekavach config show`` is pasted into bug reports and hosted CI logs (CWE-532, CWE-200).
Tables and origin comments are laid out here; ``tomli_w`` only formats values, so the output is
valid TOML that ``tomllib`` reads back. ``None`` values are omitted from TOML (TOML has no null)
and kept as ``null`` in JSON.
"""

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal

import tomli_w

from codekavach.config.masking import mask_layer_data, mask_settings
from codekavach.config.provenance import Layer, Origin

if TYPE_CHECKING:
    from codekavach.config.loader import LoadedConfig

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_COMMENT_COLUMN = 24


class UnknownSectionError(ValueError):
    """``--section`` names no top-level table of the settings."""


def _key(name: str) -> str:
    return name if _BARE_KEY.match(name) else json.dumps(name, ensure_ascii=False)


def _drop_none(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(item) for item in value if item is not None]
    return value


def _value(value: Any) -> str:
    return tomli_w.dumps({"v": value}).removeprefix("v = ").rstrip("\n")


def _origin_comment(
    key: str, origins: Mapping[str, Origin], locked: frozenset[str], policy_source: str | None
) -> str:
    origin = origins.get(key, Origin(layer="default"))
    if key in locked:
        source = origin.source if origin.layer == "org-policy" else policy_source
        return f"org-policy (locked): {source}"
    text: str = origin.layer
    if origin.source:
        location = origin.source if origin.line is None else f"{origin.source}:{origin.line}"
        text = f"{text}: {location}"
    extra = [name for name in origin.contributors if name != origin.layer]
    if extra:
        text += f" (+ {', '.join(extra)})"
    return text


def _toml_lines(
    data: Mapping[str, Any],
    prefix: tuple[str, ...],
    comment: Any,
) -> Iterator[str]:
    tables = [(k, v) for k, v in data.items() if isinstance(v, Mapping)]
    for name, value in data.items():
        if isinstance(value, Mapping):
            continue
        line = f"{_key(name)} = {_value(value)}"
        if comment is not None:
            text = comment(".".join((*prefix, name)))
            line = f"{line.ljust(_COMMENT_COLUMN)}  # {text}"
        yield line
    for name, value in tables:
        path = (*prefix, name)
        has_scalars = any(not isinstance(v, Mapping) for v in value.values())
        if has_scalars or not value:
            yield ""
            yield f"[{'.'.join(_key(part) for part in path)}]"
        yield from _toml_lines(value, path, comment)


def _to_toml(data: Mapping[str, Any], *, comment: Any = None, header: Sequence[str] = ()) -> str:
    lines = [f"# {line}" for line in header]
    lines.extend(_toml_lines(_drop_none(data), (), comment))
    while lines and not lines[0]:
        lines.pop(0)
    text = "\n".join(line for index, line in enumerate(lines) if line or index > 0)
    return re.sub(r"\n{3,}", "\n\n", text).strip("\n") + "\n"


def _section(data: dict[str, Any], section: str | None) -> dict[str, Any]:
    if section is None:
        return data
    if section not in data or not isinstance(data[section], Mapping):
        raise UnknownSectionError(section)
    return {section: data[section]}


def _header(loaded: "LoadedConfig") -> list[str]:
    selection = ""
    if loaded.profile_origin is not None and loaded.profile_origin.source:
        origin = loaded.profile_origin
        where = origin.source if origin.line is None else f"{origin.source}:{origin.line}"
        selection = f" (selected by {where})"
    policies = ", ".join(f"{p.policy.organisation} ({p.path})" for p in loaded.org_policies)
    return [
        f"CodeKavach effective configuration; profile: {loaded.profile or 'none'}{selection}",
        f"organisation policy: {policies or 'none'}",
        f"project trust: {loaded.project_trust}",
    ]


def render_toml(
    loaded: "LoadedConfig",
    *,
    origins: bool,
    section: str | None,
    reveal_domain_terms: bool = False,
    secrets: Sequence[Mapping[str, str]] | None = None,
) -> str:
    """The masked effective settings as TOML, optionally with a trailing origin comment per key.

    Raises:
        UnknownSectionError: ``section`` is not a top-level table.
    """
    data = _section(
        mask_settings(loaded.settings, reveal_domain_terms=reveal_domain_terms), section
    )
    comment = None
    header: list[str] = []
    if origins:
        policy_source = str(loaded.org_policies[0].path) if loaded.org_policies else None
        locked = frozenset(loaded.locked_keys)

        known = dict(loaded.origins)
        if loaded.profile_origin is not None:
            known["profile"] = loaded.profile_origin  # the loader keeps the name in the defaults

        def comment(key: str) -> str:
            return _origin_comment(key, known, locked, policy_source)

        header = _header(loaded)
    text = _to_toml(data, comment=comment, header=header)
    if secrets is not None:
        text += "\n# secrets (references tried, state; values are never shown)\n"
        text += "".join(
            f"# {row['group']} {row['name']} {row['ref'] or '(no key required)'}: {row['state']}\n"
            for row in secrets
        )
    return text


def _origin_json(origin: Origin) -> dict[str, Any]:
    return {
        "layer": origin.layer,
        "source": origin.source,
        "line": origin.line,
        "contributors": list(origin.contributors),
    }


def render_json(
    loaded: "LoadedConfig",
    *,
    section: str | None,
    reveal_domain_terms: bool = False,
    secrets: Sequence[Mapping[str, str]] | None = None,
) -> str:
    """The masked effective settings with origins, locks, policies, trust and warnings as JSON.

    Raises:
        UnknownSectionError: ``section`` is not a top-level table.
    """
    settings = _section(
        mask_settings(loaded.settings, reveal_domain_terms=reveal_domain_terms), section
    )
    origins = {
        key: _origin_json(origin)
        for key, origin in sorted(loaded.origins.items())
        if section is None or key == section or key.startswith(f"{section}.")
    }
    document: dict[str, Any] = {
        "profile": loaded.profile,
        "settings": settings,
        "origins": origins,
        "locked_keys": sorted(loaded.locked_keys),
        "org_policies": [
            {
                "organisation": p.policy.organisation,
                "path": str(p.path),
                "sha256": p.sha256,
                "enforcement": p.policy.enforcement,
                "signature": p.signature,
            }
            for p in loaded.org_policies
        ],
        "project_trust": loaded.project_trust,
        "warnings": [issue.to_dict() for issue in loaded.warnings],
    }
    if secrets is not None:
        document["secrets"] = [dict(row) for row in secrets]
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def render_layer(layer: Layer, *, fmt: Literal["toml", "json"]) -> str:
    """The raw contribution of one layer, masked with ``mask_layer_data``."""
    data = mask_layer_data(layer.data)
    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    return _to_toml(data)
