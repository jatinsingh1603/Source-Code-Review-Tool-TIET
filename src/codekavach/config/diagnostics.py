"""Readable configuration diagnostics, unknown-key hints and deprecated-key migration (E03-22).

Owning epic: E03.

``format_issues`` renders issues in a compiler-style layout shared by the CLI, the server and the
editor extension, so it imports no terminal library::

    error[CK-CFG-002]: unknown key 'privacy.levle'
      --> /repo/codekavach.toml:14
      hint: did you mean 'privacy.level'?

    1 problem (1 error, 0 warnings)

The formatter prints what an issue contains and adds nothing; keeping values out of messages is
the job of whoever creates the issue (CWE-532). Suggestions name only keys of the model.
"""

import difflib
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from pydantic import BaseModel

from codekavach.config.errors import ConfigErrorCode, ConfigIssue
from codekavach.config.introspect import iter_fields, resolve_field
from codekavach.config.provenance import Layer
from codekavach.config.toml_source import locate_key

# Old dotted key to new dotted key. Empty in v1.0; the first rename is a one-line change here.
DEPRECATED_KEYS: dict[str, str] = {}

SUGGESTION_CUTOFF = 0.75
_RED = "\x1b[31m"
_YELLOW = "\x1b[33m"
_RESET = "\x1b[0m"
_HINT_PREFIX = "  hint: "


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _headline(issue: ConfigIssue, colour: bool) -> str:
    label: str = issue.severity
    if colour:
        label = f"{_RED if issue.severity == 'error' else _YELLOW}{label}{_RESET}"
    message = issue.message
    if issue.key and issue.key not in message:
        message = f"{message} ({issue.key})"
    return f"{label}[{issue.code.value}]: {message}"


def _render(issue: ConfigIssue, colour: bool) -> str:
    lines = [_headline(issue, colour)]
    if issue.source is not None:
        location = issue.source if issue.line is None else f"{issue.source}:{issue.line}"
        lines.append(f"  --> {location}")
    if issue.hint:
        first, *rest = issue.hint.split("\n")
        lines.append(f"{_HINT_PREFIX}{first}")
        lines.extend(f"{' ' * len(_HINT_PREFIX)}{line}" for line in rest)
    return "\n".join(lines)


def format_issues(issues: Sequence[ConfigIssue], *, colour: bool = False) -> str:
    """Render issues: errors first, then warnings, each in the given order, then a summary.

    An empty sequence gives an empty string. With ``colour`` only the words ``error`` and
    ``warning`` of each headline are wrapped in ANSI red and yellow.
    """
    if not issues:
        return ""
    errors = [issue for issue in issues if issue.severity == "error"]
    warnings = [issue for issue in issues if issue.severity != "error"]
    blocks = [_render(issue, colour) for issue in (*errors, *warnings)]
    summary = (
        f"{_plural(len(issues), 'problem')} "
        f"({_plural(len(errors), 'error')}, {_plural(len(warnings), 'warning')})"
    )
    return "\n\n".join([*blocks, summary])


# --- unknown-key suggestions -------------------------------------------------------------------


def _candidates(model: type[BaseModel]) -> list[str]:
    """Templated leaf keys and every table above them, without duplicates."""
    keys: dict[str, None] = {}
    for ref in iter_fields(model):
        parts = ref.key.split(".")
        for length in range(1, len(parts) + 1):
            keys.setdefault(".".join(parts[:length]), None)
    return list(keys)


def _split_parent(key: str) -> tuple[str, str]:
    parent, _, last = key.rpartition(".")
    return parent, last


def suggest_key(unknown: str, model: type[BaseModel]) -> str | None:
    """The closest known key to ``unknown``, rebuilt concretely, or ``None``.

    Siblings in the same table are tried first (including the fields of a mapping entry or a
    list item, such as ``llm.providers.lab.model``), then every key of the model.
    """
    candidates = _candidates(model)
    parent, last = _split_parent(unknown)
    template_parent = ""
    if parent:
        ref = resolve_field(model, parent)
        template_parent = ref.key if ref is not None else ""
    if not parent or template_parent:
        siblings = [
            name
            for candidate in candidates
            for candidate_parent, name in [_split_parent(candidate)]
            if candidate_parent == template_parent and "*" not in name
        ]
        match = difflib.get_close_matches(last, siblings, n=1, cutoff=SUGGESTION_CUTOFF)
        if match:
            return f"{parent}.{match[0]}" if parent else match[0]
    concrete = [key for key in candidates if "*" not in key and "[]" not in key]
    match = difflib.get_close_matches(unknown, concrete, n=1, cutoff=SUGGESTION_CUTOFF)
    return match[0] if match else None


def unknown_key_hint(unknown: str, model: type[BaseModel]) -> str | None:
    """``did you mean '<key>'?`` for the closest known key, or ``None``."""
    suggestion = suggest_key(unknown, model)
    return f"did you mean '{suggestion}'?" if suggestion else None


# --- deprecated keys ---------------------------------------------------------------------------

_MISSING = object()


def _get(data: Mapping[str, Any], key: str) -> Any:
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _without(data: Mapping[str, Any], parts: list[str]) -> dict[str, Any]:
    """A copy of ``data`` without the key at ``parts``; tables it leaves empty are dropped."""
    head, *rest = parts
    copy = dict(data)
    if not rest:
        copy.pop(head, None)
        return copy
    child = _without(copy[head], rest)
    if child:
        copy[head] = child
    else:
        copy.pop(head)
    return copy


def _with(data: Mapping[str, Any], parts: list[str], value: Any) -> dict[str, Any]:
    head, *rest = parts
    copy = dict(data)
    if not rest:
        copy[head] = value
        return copy
    child = copy.get(head)
    copy[head] = _with(child if isinstance(child, Mapping) else {}, rest, value)
    return copy


def apply_deprecations(
    layer: Layer, mapping: Mapping[str, str] = DEPRECATED_KEYS
) -> tuple[Layer, list[ConfigIssue]]:
    """Move deprecated keys of a raw layer to their new names, with warning CK-CFG-006.

    When both the old and the new key are present the new one wins and the old one is dropped
    with a warning. The input layer is not mutated.
    """
    data: Mapping[str, Any] = layer.data
    warnings: list[ConfigIssue] = []
    for old, new in mapping.items():
        value = _get(data, old)
        if value is _MISSING:
            continue
        both = _get(data, new) is not _MISSING
        data = _without(data, old.split("."))
        if both:
            message = f"'{old}' is deprecated and ignored because '{new}' is also set"
        else:
            data = _with(data, new.split("."), value)
            message = f"'{old}' is deprecated; use '{new}'"
        warnings.append(
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_006,
                severity="warning",
                message=message,
                key=old,
                source=layer.key_sources.get(old, layer.source),
                line=locate_key(layer.text, old) if layer.text is not None else None,
            )
        )
    if not warnings:
        return layer, []
    return replace(layer, data=data), warnings
