"""Generate the configuration key reference from the settings models (E03-40).

Owning epic: E03.

Usage::

    python -m codekavach.config.docgen [--check] [--output docs/configuration/reference.md]

``render_reference()`` walks ``Settings`` with ``iter_fields`` and writes one table per section:
dotted key, type, default, environment variable, markers and description. It then appends the
tables of the reserved ``CODEKAVACH_*`` process variables, the flag-to-key map, the conventional
provider key variables and the tighten-only keys, all imported from the modules that own them.
The output is deterministic (no timestamps, no absolute paths), and ``--check`` fails when the
committed file differs. The error-code catalogue next to it is written by hand and checked
against ``ConfigErrorCode`` by a test.
"""

import argparse
import enum
import fnmatch
import sys
import types
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePath
from typing import Annotated, Any, Literal, Union, get_args, get_origin

import tomli_w
from pydantic import AnyHttpUrl, BaseModel
from pydantic_core import PydanticUndefined

from codekavach.config.env_source import RESERVED_ENV, RESERVED_ENV_MEANINGS, env_var_name
from codekavach.config.introspect import FieldRef, iter_fields
from codekavach.config.keys import DEFAULT_KEY_ENV, SecretRef
from codekavach.config.models.root import Settings
from codekavach.config.overrides import FLAG_TO_KEY
from codekavach.config.trust import TIGHTEN_ONLY
from codekavach.core.models import PrivacyLevel

DEFAULT_OUTPUT = Path("docs/configuration/reference.md")
REFRESH_COMMAND = "uv run python -m codekavach.config.docgen"
LONG_DEFAULT = 80
MAX_INLINE_MEMBERS = 8
GENERAL = "general"
GENERAL_KEYS = ("config_version", "profile", "profiles")
MARKER_ORDER = ("sensitive", "restricted", "tighten-only", "union", "volatile")
MARKER_TEXT = {
    "sensitive": "value is masked in every output",
    "restricted": "an untrusted project file may not set it",
    "tighten-only": "a project file may tighten it but not loosen it",
    "union": "layers combine by union instead of replacing",
    "volatile": "excluded from the settings fingerprint",
}
_COMPARATOR_TEXT = {
    "_level_looser": "may not lower the level",
    "_switched_on": "may not switch it on",
    "_skips_protected": "may not skip a protected stage",
}
HEADER = """# Configuration reference

This page is produced from the settings models by `{command}` and must not be edited by hand.
A test fails when it is stale. Settings are read from `codekavach.toml`, the user configuration
file, profiles, the environment and command-line flags, in that order of precedence (ADR-0006).
The error codes are in [error-codes.md](error-codes.md).

**Notation.** `a.b` is the key `b` in the table `[a]`. In keys, `*` stands for a name you choose
(`llm.providers.*.base_url` is the `base_url` of each provider you define) and `[]` for one item
of a list of tables (`privacy.paths[].level`). Keys with a `*` or `[]` have no environment
variable. Other keys are set with `CODEKAVACH_<SECTION>__<KEY>`, for example
`CODEKAVACH_SCAN__JOBS`; `<SECTION>` and `<KEY>` are the upper-case names.
"""


# --- types and defaults --------------------------------------------------------------------


def _is_union(origin: Any) -> bool:
    return origin in (Union, types.UnionType)


def type_name(annotation: Any) -> str:  # noqa: PLR0911, PLR0912 - one branch per kind of type
    """A compact type: ``str``, ``list[str]``, ``L0..L4``, ``path``, ``secret reference``."""
    if annotation == SecretRef:
        return "secret reference"
    origin = get_origin(annotation)
    if origin is Annotated:
        return type_name(get_args(annotation)[0])
    if _is_union(origin):
        members = [arg for arg in get_args(annotation) if arg is not type(None)]
        names = [type_name(member) for member in members]
        if len(members) != len(get_args(annotation)):
            names.append("unset")
        return " | ".join(names)
    if origin is Literal:
        return " | ".join(str(arg) for arg in get_args(annotation))
    if origin in (list, tuple, set, frozenset):
        inner = get_args(annotation)
        return f"list[{type_name(inner[0])}]" if inner else "list"
    if origin is dict:
        return "table"
    if isinstance(annotation, type):
        if annotation is PrivacyLevel:
            return "L0..L4"
        if issubclass(annotation, enum.Enum):
            values = [str(member.value) for member in annotation]
            return " | ".join(values) if len(values) <= MAX_INLINE_MEMBERS else annotation.__name__
        if issubclass(annotation, PurePath):
            return "path"
        if annotation is AnyHttpUrl:
            return "url"
        if issubclass(annotation, BaseModel):
            return "table"
        return annotation.__name__
    return str(annotation)


def _plain(value: Any) -> Any:  # noqa: PLR0911 - one branch per kind of value
    """``value`` as TOML-compatible data."""
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, BaseModel):
        return _plain(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items() if item is not None}
    if isinstance(value, set | frozenset):
        return sorted(_plain(item) for item in value)
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    if isinstance(value, bool | int | float | str):
        return value
    return str(value)  # for example a URL


def default_text(ref: FieldRef) -> str:
    """The default of a field as a TOML fragment: ``unset``, ``required``, ``["html", "json"]``."""
    field = ref.field
    if field.is_required():
        return "required"
    if field.default_factory is not None:
        value: Any = field.default_factory()  # type: ignore[call-arg]
    else:
        value = field.default
    if value is None or value is PydanticUndefined:
        return "unset"
    return _fragment(_plain(value))


def _fragment(value: Any) -> str:
    """``value`` as one TOML value; tables are written inline (``{ a = 1 }``)."""
    if isinstance(value, Mapping):
        if not value:
            return "{}"
        inner = ", ".join(f"{key} = {_fragment(item)}" for key, item in value.items())
        return "{ " + inner + " }"
    if isinstance(value, list):
        return "[" + ", ".join(_fragment(item) for item in value) + "]"
    return tomli_w.dumps({"v": value}).removeprefix("v = ").rstrip("\n")


# --- the key tables --------------------------------------------------------------------------


def _templated(key: str) -> bool:
    return "*" in key or "[" in key


def _tighten_only(key: str) -> bool:
    return any(fnmatch.fnmatchcase(key, pattern) for pattern in TIGHTEN_ONLY)


def markers_text(ref: FieldRef) -> str:
    """The markers of a key in a fixed order, for example ``restricted, volatile``."""
    found = set(ref.markers)
    if _tighten_only(ref.key):
        found.add("tighten-only")
    return ", ".join(marker for marker in MARKER_ORDER if marker in found)


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def _code(text: str) -> str:
    return f"`{text.replace('|', chr(92) + '|')}`"


def _section_of(key: str) -> str:
    head = key.split(".", maxsplit=1)[0].split("[", maxsplit=1)[0]
    return GENERAL if head in GENERAL_KEYS else head


def _description(ref: FieldRef) -> str:
    return _cell(ref.field.description or "")


def _section_table(title: str, refs: Sequence[FieldRef]) -> list[str]:
    description = ""
    if title in Settings.model_fields:
        description = Settings.model_fields[title].description or ""
    lines = [f"## `[{title}]`" if title != GENERAL else "## General", ""]
    if description:
        lines += [description, ""]
    lines += [
        "| Key | Type | Default | Environment variable | Markers | Description |",
        "|-----|------|---------|----------------------|---------|-------------|",
    ]
    notes: list[tuple[int, str, str]] = []
    for ref in refs:
        default = default_text(ref)
        if len(default) > LONG_DEFAULT:
            notes.append((len(notes) + 1, ref.key, default))
            default_cell = f"see note {len(notes)}"
        else:
            default_cell = _code(default) if default not in {"unset", "required"} else default
        variable = "" if _templated(ref.key) else _code(env_var_name(ref.key))
        lines.append(
            f"| {_code(ref.key)} | {_cell(type_name(ref.annotation))} | {default_cell} | "
            f"{variable} | {markers_text(ref)} | {_description(ref)} |"
        )
    if notes:
        lines += ["", "Defaults too long for the table:", ""]
        lines += [f"{number}. {_code(key)}: {_code(text)}" for number, key, text in notes]
    return [*lines, ""]


def _sections() -> list[tuple[str, list[FieldRef]]]:
    grouped: dict[str, list[FieldRef]] = {}
    for ref in iter_fields(Settings):
        grouped.setdefault(_section_of(ref.key), []).append(ref)
    order = [GENERAL, *Settings.model_fields]
    return [(name, grouped[name]) for name in order if name in grouped]


def _marker_legend() -> list[str]:
    lines = ["## Markers", "", "| Marker | Meaning |", "|--------|---------|"]
    lines += [f"| {name} | {MARKER_TEXT[name]} |" for name in MARKER_ORDER]
    return [*lines, ""]


# --- the constants tables --------------------------------------------------------------------


def _reserved_table() -> list[str]:
    lines = [
        "## Reserved process variables",
        "",
        "Other `CODEKAVACH_*` variables are errors (CK-CFG-060), so a misspelt setting is not "
        "silently ignored.",
        "",
        "| Variable | Meaning |",
        "|----------|---------|",
    ]
    lines += [
        f"| {_code(name)} | {_cell(RESERVED_ENV_MEANINGS[name])} |" for name in sorted(RESERVED_ENV)
    ]
    return [*lines, ""]


def _flag_table() -> list[str]:
    lines = [
        "## Command-line flags and the keys they set",
        "",
        "| Flag | Sets | Notes |",
        "|------|------|-------|",
    ]
    for flag in FLAG_TO_KEY.values():
        keys = ", ".join(_code(key) for key in flag.keys)
        if flag.boolean:
            notes = f"sets the keys to `{str(flag.fixed).lower()}` when given"
            if flag.optional_keys:
                notes += "; keys that are not part of this build are skipped"
        else:
            notes = ""
        lines.append(f"| {_code(flag.flag)} | {keys} | {notes} |")
    return [*lines, ""]


def _provider_key_table() -> list[str]:
    lines = [
        "## Conventional provider key variables",
        "",
        "When a provider has no `api_key` reference, the variables below are tried in order. "
        "Configuration holds a reference to a key, not the key: a plaintext key is refused "
        "(CK-CFG-010, ADR-0006 D4).",
        "",
        "| Provider kind | Variables |",
        "|---------------|-----------|",
    ]
    lines += [
        f"| {_code(kind)} | {', '.join(_code(name) for name in names)} |"
        for kind, names in DEFAULT_KEY_ENV.items()
    ]
    return [*lines, ""]


def _tighten_table() -> list[str]:
    lines = [
        "## Tighten-only keys",
        "",
        "A project file, and a profile it selects, may tighten these keys but not loosen them "
        "(CK-CFG-041).",
        "",
        "| Key | Rule |",
        "|-----|------|",
    ]
    for key, comparator in TIGHTEN_ONLY.items():
        rule = _COMPARATOR_TEXT.get(comparator.__name__, "may only be tightened")
        lines.append(f"| {_code(key)} | a project file {rule} |")
    return [*lines, ""]


def render_reference() -> str:
    """The whole reference page as Markdown."""
    lines = [HEADER.format(command=REFRESH_COMMAND).rstrip("\n"), ""]
    for title, refs in _sections():
        lines += _section_table(title, refs)
    for block in (_marker_legend(), _reserved_table(), _flag_table(), _provider_key_table(),
                  _tighten_table()):  # fmt: skip
        lines += block
    return "\n".join(lines).rstrip("\n") + "\n"


# --- command line ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description="Generate the configuration key reference.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="exit 1 when the file is stale")
    args = parser.parse_args(argv)
    text = render_reference()
    if args.check:
        current = args.output.read_bytes() if args.output.is_file() else b""
        if current == text.encode("utf-8"):
            return 0
        sys.stdout.write(f"{args.output} is stale; run: {REFRESH_COMMAND}\n")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    sys.stdout.write(f"{args.output}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
