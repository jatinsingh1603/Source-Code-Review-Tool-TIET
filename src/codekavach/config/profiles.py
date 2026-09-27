"""Named profiles: overlays of settings that sit above the project file (ADR decision D2).

Owning epic: E03.

Selection order, first set wins: ``--profile``, ``CODEKAVACH_PROFILE``, the ``profile`` key of the
project file, the ``profile`` key of the user file. An empty string means "no profile".

Built-in profiles ship as package data in ``builtin_profiles/``. User-defined profiles are
``[profiles.<name>]`` tables with optional ``extends`` (one parent, built-in or user-defined) and
``description`` keys. A user-defined profile may not reuse a built-in name, so a repository cannot
redefine a profile that an operator selects by name as something weaker (code 022).
"""

import difflib
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Literal

from codekavach.config.errors import ConfigErrorCode, ProfileError
from codekavach.config.merge import deep_merge
from codekavach.config.provenance import Layer, Origin

BUILTIN_PROFILES: tuple[str, ...] = ("ci", "demo")
PROFILE_ENV = "CODEKAVACH_PROFILE"
META_KEYS = frozenset({"extends", "description"})
FORBIDDEN_KEYS = frozenset({"profile", "profiles", "config_version"})
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


@dataclass(frozen=True, slots=True)
class ProfileInfo:
    """What ``codekavach config profiles`` lists."""

    name: str
    kind: Literal["built-in", "user-defined"]
    defined_in: str
    extends: str | None = None
    description: str | None = None


def load_builtin_profile(name: str) -> dict[str, Any]:
    """The overlay of a built-in profile, read from the installed package data."""
    if name not in BUILTIN_PROFILES:
        raise _unknown(name, BUILTIN_PROFILES)
    resource = files("codekavach.config").joinpath("builtin_profiles", f"{name}.toml")
    return tomllib.loads(resource.read_text(encoding="utf-8"))


def _unknown(name: str, known: tuple[str, ...] | list[str]) -> ProfileError:
    close = difflib.get_close_matches(name, known, n=1)
    return ProfileError.single(
        ConfigErrorCode.CK_CFG_020,
        f"unknown profile; available profiles: {', '.join(sorted(known))}",
        key="profile",
        hint=f"did you mean {close[0]}?" if close else None,
    )


def select_profile_name(
    cli: str | None,
    env: Mapping[str, str],
    project: Mapping[str, Any] | None,
    user: Mapping[str, Any] | None,
) -> tuple[str | None, Origin]:
    """The selected profile name (``None`` for none) and the origin of the selection."""
    candidates: list[tuple[Any, Origin]] = [
        (cli, Origin(layer="cli", source="--profile")),
        (env.get(PROFILE_ENV), Origin(layer="env", source=PROFILE_ENV)),
        ((project or {}).get("profile"), Origin(layer="project")),
        ((user or {}).get("profile"), Origin(layer="user")),
    ]
    for value, origin in candidates:
        if value is None:
            continue
        if not isinstance(value, str):
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_003, "profile must be a string", key="profile"
            )
        return (value.strip() or None), origin
    return None, Origin(layer="default")


def check_user_defined(user_defined: Mapping[str, Any]) -> None:
    """Validate names and shapes of ``[profiles.*]`` tables.

    Raises:
        ProfileError: 022 for a built-in name, 003 for a bad name, shape or forbidden key.
    """
    for name, table in user_defined.items():
        if name in BUILTIN_PROFILES:
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_022,
                "a user-defined profile may not reuse a built-in profile name",
                key=f"profiles.{name}",
            )
        if not _NAME.match(name):
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_003,
                "profile names match ^[a-z][a-z0-9-]{0,31}$",
                key="profiles",
            )
        if not isinstance(table, Mapping):
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_003, "a profile must be a table", key=f"profiles.{name}"
            )
        for key in FORBIDDEN_KEYS & table.keys():
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_003,
                f"a profile may not set {key}",
                key=f"profiles.{name}.{key}",
            )
        for key in META_KEYS & table.keys():
            if not isinstance(table[key], str):
                raise ProfileError.single(
                    ConfigErrorCode.CK_CFG_003,
                    f"{key} must be a string",
                    key=f"profiles.{name}.{key}",
                )


def resolve_profile(
    name: str,
    user_defined: Mapping[str, Mapping[str, Any]],
    *,
    union_keys: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """The overlay of ``name`` with its ``extends`` chain applied, parent first.

    Raises:
        ProfileError: 020 for an unknown name, 021 for a cycle or an unknown parent.
    """
    chain: list[str] = []
    current: str | None = name
    while current is not None:
        if current in chain:
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_021,
                f"profile inheritance cycle: {' -> '.join([*chain, current])}",
                key=f"profiles.{chain[-1]}.extends",
            )
        if current in user_defined:
            chain.append(current)
            current = user_defined[current].get("extends")
        elif current in BUILTIN_PROFILES:
            chain.append(current)
            current = None
        elif not chain:
            raise _unknown(current, [*BUILTIN_PROFILES, *user_defined])
        else:
            raise ProfileError.single(
                ConfigErrorCode.CK_CFG_021,
                "profile extends an unknown profile",
                key=f"profiles.{chain[-1]}.extends",
            )
    overlay: dict[str, Any] = {}
    for link in reversed(chain):
        data = (
            {k: v for k, v in user_defined[link].items() if k not in META_KEYS}
            if link in user_defined
            else load_builtin_profile(link)
        )
        overlay = deep_merge(overlay, data, union_keys=union_keys)
    return overlay


def build_profile_layer(
    name: str,
    user_defined: Mapping[str, Mapping[str, Any]],
    *,
    sources: Mapping[str, str] | None = None,
    union_keys: frozenset[str] = frozenset(),
) -> Layer:
    """The ``profile`` layer for ``name``."""
    check_user_defined(user_defined)
    data = resolve_profile(name, user_defined, union_keys=union_keys)
    if name in user_defined:
        source = f"{(sources or {}).get(name, 'profiles')}#profiles.{name}"
    else:
        source = f"builtin:{name}"
    return Layer(name="profile", source=source, data=data)


def list_profiles(
    user_defined: Mapping[str, Mapping[str, Any]], *, sources: Mapping[str, str] | None = None
) -> list[ProfileInfo]:
    """Built-in profiles, then user-defined ones, sorted by name within each group."""
    infos = [ProfileInfo(name, "built-in", f"builtin:{name}") for name in sorted(BUILTIN_PROFILES)]
    for name in sorted(user_defined):
        table = user_defined[name]
        infos.append(
            ProfileInfo(
                name=name,
                kind="user-defined",
                defined_in=(sources or {}).get(name, "profiles"),
                extends=table.get("extends"),
                description=table.get("description"),
            )
        )
    return infos
