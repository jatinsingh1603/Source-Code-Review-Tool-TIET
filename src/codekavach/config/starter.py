"""The commented starter ``codekavach.toml`` written by ``codekavach init`` (E03-37).

Owning epic: E03.

The file is rendered from the settings models (field descriptions and defaults), so it cannot
drift from them. Line conventions, which the drift test relies on:

- ``#:schema`` on line 1 is the editor directive (Taplo, Even Better TOML);
- ``#~ `` starts prose: section introductions and field descriptions;
- ``# key = value`` is a commented-out setting showing its default;
- ``#? key = value`` is an optional setting without a default, with a placeholder value;
- uncommented lines are active settings;
- example regions (``#~ example: <table>`` to ``#~ end of example``) hold hand-written, commented
  examples for tables that defaults cannot describe (maps of providers or engines, path rules,
  profiles).

Keys never appear with a value here, only references (``env:``, ``keyring:``, ``file:``).
"""

import re
from collections.abc import Iterator, Mapping
from types import MappingProxyType, NoneType, UnionType
from typing import Annotated, Any, Union, get_args, get_origin

import tomli_w
from pydantic import BaseModel
from pydantic.fields import FieldInfo

from codekavach.config.constants import SCHEMA_ID
from codekavach.config.models.root import Settings

HEADER = (
    "CodeKavach configuration. Reference: docs/configuration/reference.md",
    "Precedence: defaults < user config < this file < profile < CODEKAVACH_* env < CLI flags.",
    'Never put API keys here. Use references: "env:NAME", "keyring:codekavach/NAME" or '
    '"file:/path".',
)
EXAMPLE_BEGIN = "#~ example: "
EXAMPLE_END = "#~ end of example"

SECTION_INTROS: Mapping[str, str] = MappingProxyType(
    {
        "project": "Who and what is being reviewed; shown on the report cover.",
        "scan": "Which files are read and how long a scan may take.",
        "privacy": "What may leave the machine. L3 sends a redacted, pseudonymised minimal slice.",
        "llm": "Language models. Keys are references, never values.",
        "reporting": "Report formats, destination and cover details.",
        "engines": "Deterministic analysers and their options.",
        "integrations": "External systems that receive findings; all are off by default.",
        "plugins": "Which installed plugins may load.",
        "logging": "Diagnostics on stderr; never contains client code.",
        "profiles": "Named overlays selected with --profile or the profile key above.",
    }
)

EXAMPLE_BLOCKS: Mapping[str, str] = MappingProxyType(
    {
        "privacy.paths": (
            "# [[privacy.paths]]\n"
            '# pattern = "src/payments/**"\n'
            '# level = "L4"\n'
            "#\n"
            "# [[privacy.paths]]\n"
            '# pattern = "config/hsm/**"\n'
            "# never_send = true\n"
        ),
        "llm.providers": (
            "# [llm.providers.primary]\n"
            '# kind = "anthropic"\n'
            '# model = "claude-sonnet-5"\n'
            # pragma: allowlist nextline secret
            '# api_key = "env:ANTHROPIC_API_KEY"\n'
            "#\n"
            "# [llm.providers.local]\n"
            '# kind = "ollama"\n'
            '# model = "llama3.1"\n'
            '# base_url = "http://127.0.0.1:11434"\n'
        ),
        "engines.options": (
            '# [engines.options.semgrep]\n# timeout_seconds = 900\n# args = ["--metrics=off"]\n'
        ),
        "profiles": (
            "# [profiles.nightly]\n"
            '# extends = "ci"\n'
            '# description = "Nightly pipeline run"\n'
            "#\n"
            "# [profiles.nightly.scan]\n"
            '# fail_on = "medium"\n'
        ),
    }
)

# Placeholders for secret references without a default: a reference, never a value.
SECRET_PLACEHOLDERS: Mapping[str, str] = MappingProxyType(
    {
        "api_key": "env:ANTHROPIC_API_KEY",  # pragma: allowlist secret
        "token": "env:GITHUB_TOKEN",  # pragma: allowlist secret
        "passphrase": "env:CODEKAVACH_VAULT_PASSPHRASE",  # pragma: allowlist secret
    }
)
_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _strip(annotation: Any) -> Any:
    """The annotation without ``Annotated`` wrappers and ``None`` members."""
    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    if get_origin(annotation) in (Union, UnionType):
        members = [m for m in get_args(annotation) if m is not NoneType]
        if len(members) == 1:
            return _strip(members[0])
    return annotation


def _model(annotation: Any) -> type[BaseModel] | None:
    stripped = _strip(annotation)
    return stripped if isinstance(stripped, type) and issubclass(stripped, BaseModel) else None


def _entry_model(annotation: Any) -> type[BaseModel] | None:
    """The model of the values of a ``dict[..., Model]`` or the items of a ``list[Model]``."""
    stripped = _strip(annotation)
    args = get_args(stripped)
    if get_origin(stripped) is dict and len(args) == 2:
        return _model(args[1])
    if get_origin(stripped) is list and args:
        return _model(args[0])
    return None


def _key(name: str) -> str:
    return name if _BARE_KEY.match(name) else f'"{name}"'


def _inline(value: Any) -> str:
    """One TOML value on one line (arrays and tables inline)."""
    if isinstance(value, list):
        return "[" + ", ".join(_inline(item) for item in value) + "]"
    if isinstance(value, Mapping):
        return "{" + ", ".join(f"{_key(str(k))} = {_inline(v)}" for k, v in value.items()) + "}"
    return tomli_w.dumps({"v": value}).removeprefix("v = ").rstrip("\n")


def _placeholder(name: str, annotation: Any) -> str:
    if name in SECRET_PLACEHOLDERS:
        return _inline(SECRET_PLACEHOLDERS[name])
    stripped = _strip(annotation)
    if stripped is bool:
        return "false"
    if stripped is int:
        return "0"
    if stripped is float:
        return "0.0"
    if get_origin(stripped) is list:
        return "[]"
    return '""'


def _prose(text: str) -> str:
    return f"#~ {text}"


def _section_lines(
    model: type[BaseModel],
    defaults: Mapping[str, Any],
    path: tuple[str, ...],
    active: Mapping[str, str],
) -> Iterator[str]:
    """Lines of one table: its keys, example regions and sub-tables.

    Inside a table the example regions come before its sub-tables, so that uncommenting one stays
    in place; the root-level example (profiles) closes the file.
    """
    examples: list[tuple[str, FieldInfo]] = []
    tables: list[tuple[str, type[BaseModel], str | None]] = []
    for name, field in model.model_fields.items():
        dotted = ".".join((*path, name))
        nested = _model(field.annotation)
        if nested is not None:
            tables.append((name, nested, field.description))
        elif dotted in EXAMPLE_BLOCKS:
            examples.append((name, field))
        else:
            yield from _field_lines(name, field, dotted, defaults, active)
    example_lines = [line for name, field in examples for line in _example(name, field, path)]
    if path:
        yield from example_lines
    for name, nested, description in tables:
        sub_path = (*path, name)
        yield ""
        if len(sub_path) == 1 and name in SECTION_INTROS:
            yield _prose(SECTION_INTROS[name])
        if description:
            yield _prose(description)
        yield f"[{'.'.join(_key(part) for part in sub_path)}]"
        yield from _section_lines(nested, defaults.get(name) or {}, sub_path, active)
    if not path:
        yield from example_lines


def _field_lines(
    name: str,
    field: FieldInfo,
    dotted: str,
    defaults: Mapping[str, Any],
    active: Mapping[str, str],
) -> Iterator[str]:
    if field.description:
        yield _prose(field.description)
    if dotted in active:
        yield f"{_key(name)} = {active[dotted]}"
    elif defaults.get(name) is None:
        yield f"#? {_key(name)} = {_placeholder(name, field.annotation)}"
    else:
        yield f"# {_key(name)} = {_inline(defaults[name])}"


def _example(name: str, field: FieldInfo, path: tuple[str, ...]) -> Iterator[str]:
    dotted = ".".join((*path, name))
    yield ""
    if not path and name in SECTION_INTROS:
        yield _prose(SECTION_INTROS[name])
    yield f"{EXAMPLE_BEGIN}{dotted}"
    if field.description:
        yield _prose(field.description)
    entry = _entry_model(field.annotation)
    for entry_name, entry_field in entry.model_fields.items() if entry else ():
        if entry_field.description:
            yield _prose(f"{entry_name}: {entry_field.description}")
    yield from EXAMPLE_BLOCKS[dotted].rstrip("\n").split("\n")
    yield EXAMPLE_END


def render_starter(
    *, profile: str | None = None, minimal: bool = False, project_name: str | None = None
) -> str:
    """The starter file: active lines for the essentials, every other setting commented."""
    active: dict[str, str] = {
        "config_version": "1",
        "project.name": _inline(project_name or "my-project"),
        "privacy.level": _inline("L3"),
    }
    if profile is not None:
        active["profile"] = _inline(profile)
    lines = [f"#:schema {SCHEMA_ID}", *(_prose(line) for line in HEADER)]
    if minimal:
        if profile is not None:
            lines.append(f"profile = {active['profile']}")
        lines += [
            "config_version = 1",
            "",
            "[project]",
            f"name = {active['project.name']}",
            "",
            "[privacy]",
            f"level = {active['privacy.level']}",
        ]
        return "\n".join(lines) + "\n"
    defaults = Settings().model_dump(mode="json")
    lines.extend(_section_lines(Settings, defaults, (), active))
    return "\n".join(lines) + "\n"


def uncomment_defaults(text: str) -> str:
    """The drift-test view: example regions removed and every ``# key = value`` line active."""
    kept: list[str] = []
    skipping = False
    for line in text.split("\n"):
        if line.startswith(EXAMPLE_BEGIN):
            skipping = True
        if not skipping:
            kept.append(line[2:] if re.match(r"^# [A-Za-z0-9_\"-]+ = ", line) else line)
        if line == EXAMPLE_END:
            skipping = False
    return "\n".join(kept)
