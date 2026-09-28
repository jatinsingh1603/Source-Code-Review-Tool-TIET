"""The ``CODEKAVACH_*`` environment layer (ADR decision D2: above profiles, below CLI flags).

Owning epic: E03.

Settings variables have the form ``CODEKAVACH_<SECTION>__<KEY>`` (segments joined by ``__``).
An unknown or malformed settings variable is an error (CK-CFG-060), because a silently ignored
``CODEKAVACH_PRIVACY__LEVLE=L4`` would leave a scan weaker than intended. Process variables
(``CODEKAVACH_*`` without ``__``) that are not in ``RESERVED_ENV`` produce a warning with a
closest-match hint, so a misspelt organisation-policy switch is visible instead of failing open.
Values are never printed: environment variables often hold credentials (CWE-532).
"""

import difflib
import json
from collections.abc import Mapping
from types import MappingProxyType, NoneType, UnionType
from typing import Annotated, Any, Union, get_args, get_origin

from pydantic import BaseModel

from codekavach.config.constants import ENV_NESTED_DELIMITER, ENV_PREFIX
from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigIssue
from codekavach.config.introspect import iter_fields, resolve_field
from codekavach.config.models.root import Settings
from codekavach.config.provenance import Layer

# Every process variable CodeKavach understands. Other epics add their names here when they
# introduce them; the golden test in tests/unit/config/test_env_source.py lists the set.
RESERVED_ENV: frozenset[str] = frozenset(
    {
        # E03: configuration
        "CODEKAVACH_CONFIG",
        "CODEKAVACH_PROFILE",
        "CODEKAVACH_HOME",
        "CODEKAVACH_NO_USER_CONFIG",
        "CODEKAVACH_ORG_POLICY",
        "CODEKAVACH_ORG_POLICY_SHA256",
        "CODEKAVACH_ORG_POLICY_PUBKEY",
        "CODEKAVACH_TRUST_PROJECT_CONFIG",
        # E05: global options read by Click (E05-05) and process switches
        "CODEKAVACH_PRIVACY_LEVEL",
        "CODEKAVACH_PROVIDER",
        "CODEKAVACH_MODEL",
        "CODEKAVACH_OFFLINE",
        "CODEKAVACH_JSON",
        "CODEKAVACH_QUIET",
        "CODEKAVACH_VERBOSE",
        "CODEKAVACH_DEBUG",
        "CODEKAVACH_NO_COLOR",
        "CODEKAVACH_ACCEPT_EGRESS",
        # ADR-0005: logging (read by codekavach.core.log)
        "CODEKAVACH_LOG_LEVEL",
        "CODEKAVACH_LOG_FORMAT",
        "CODEKAVACH_LOG_THIRD_PARTY",
        # Test-harness switches exported by CI for the whole job
        "CODEKAVACH_PERF_FACTOR",
        "CODEKAVACH_TEST_NETWORK",
        "CODEKAVACH_UPDATE_GOLDEN",
        "CODEKAVACH_SKIP_PERF",
        "CODEKAVACH_UPDATE_SNAPSHOTS",
    }
)
SETTINGS_FORM_HINT = "settings variables use the form CODEKAVACH_<SECTION>__<KEY>"
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_ENV_LAYER_SOURCE = "environment"


class _CoercionError(ValueError):
    """The raw text does not fit the expected type; carries the type name only."""


def env_var_name(dotted_key: str) -> str:
    """The settings variable for a dotted key: ``scan.jobs`` becomes ``CODEKAVACH_SCAN__JOBS``."""
    return ENV_PREFIX + ENV_NESTED_DELIMITER.join(part.upper() for part in dotted_key.split("."))


def _strip(annotation: Any) -> Any:
    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    origin = get_origin(annotation)
    if origin in (Union, UnionType):
        members = [arg for arg in get_args(annotation) if arg is not NoneType]
        if len(members) == 1:
            return _strip(members[0])
    return annotation


def _json(raw: str, expected: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise _CoercionError(expected) from None


def _bool(raw: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise _CoercionError("a boolean (1, 0, true, false, yes, no, on or off)")


def _number(kind: type[int] | type[float], expected: str) -> Any:
    def convert(raw: str) -> Any:
        try:
            return kind(raw.strip())
        except ValueError:
            raise _CoercionError(expected) from None

    return convert


def _list(raw: str) -> list[Any]:
    text = raw.strip()
    if not text.startswith("["):
        return [item.strip() for item in text.split(",") if item.strip()]
    value = _json(text, "a JSON array")
    if not isinstance(value, list):
        raise _CoercionError("a JSON array")
    return value


def _object(raw: str) -> dict[str, Any]:
    value = _json(raw, "a JSON object")
    if not isinstance(value, dict):
        raise _CoercionError("a JSON object")
    return value


_SCALARS: dict[Any, Any] = {
    bool: _bool,
    int: _number(int, "an integer"),
    float: _number(float, "a number"),
}


def coerce_env_value(raw: str, annotation: Any) -> Any:
    """Convert the text of a variable into a value for ``annotation``.

    Booleans accept 1, 0, true, false, yes, no, on and off; lists take a JSON array or a
    comma-separated string; dictionaries and models need JSON; everything else (strings, enums,
    paths, URLs) passes as text and is validated by the settings model.

    Raises:
        ValueError: the text does not fit; the message names the expected type, not the text.
    """
    target = _strip(annotation)
    origin = get_origin(target) or target
    if target in _SCALARS:
        return _SCALARS[target](raw)
    if origin in (list, tuple, set, frozenset):
        return _list(raw)
    if origin is dict or (isinstance(target, type) and issubclass(target, BaseModel)):
        return _object(raw)
    return raw


def _known_variables() -> list[str]:
    return [env_var_name(ref.key) for ref in iter_fields(Settings) if not _templated(ref.key)]


def _templated(key: str) -> bool:
    return "*" in key or "[" in key


def _hint(name: str, candidates: list[str]) -> str | None:
    match = difflib.get_close_matches(name, candidates, n=1, cutoff=0.8)
    return f"did you mean {match[0]}?" if match else None


def _issue(
    severity: str, message: str, *, source: str, key: str | None = None, hint: str | None = None
) -> ConfigIssue:
    return ConfigIssue(
        code=ConfigErrorCode.CK_CFG_060,
        severity=severity,  # type: ignore[arg-type]
        message=message,
        key=key,
        source=source,
        hint=hint,
    )


def _set(data: dict[str, Any], key: str, value: Any) -> None:
    node = data
    *parents, leaf = key.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value


def env_layer(
    env: Mapping[str, str], model: type[Settings] = Settings
) -> tuple[Layer | None, list[ConfigIssue]]:
    """Build the ``env`` layer from ``CODEKAVACH_*`` variables.

    Returns the layer (or ``None`` when no settings variable is set) and the warnings about
    unknown process variables.

    Raises:
        ConfigError: CK-CFG-060 for every unknown or malformed settings variable.
    """
    errors: list[ConfigIssue] = []
    warnings: list[ConfigIssue] = []
    data: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for name in sorted(env):
        if not name.startswith(ENV_PREFIX):
            continue
        raw = env[name]
        if ENV_NESTED_DELIMITER not in name:
            if name not in RESERVED_ENV:
                hint = _hint(name, sorted(RESERVED_ENV)) or _hint(name, _known_variables())
                hint = f"{hint} {SETTINGS_FORM_HINT}" if hint else SETTINGS_FORM_HINT
                warnings.append(
                    _issue("warning", "unknown CodeKavach process variable", source=name, hint=hint)
                )
            continue
        if raw == "":
            continue
        segments = name[len(ENV_PREFIX) :].split(ENV_NESTED_DELIMITER)
        if any(not segment for segment in segments):
            errors.append(_issue("error", "malformed settings variable", source=name))
            continue
        key = ".".join(segment.lower() for segment in segments)
        ref = resolve_field(model, key)
        if ref is None:
            errors.append(
                _issue(
                    "error",
                    "unknown settings variable",
                    source=name,
                    hint=_hint(name, _known_variables()),
                )
            )
            continue
        try:
            value = coerce_env_value(raw, ref.annotation)
        except _CoercionError as exc:
            errors.append(_issue("error", f"expected {exc}", source=name, key=key))
            continue
        _set(data, key, value)
        sources[key] = name
    if errors:
        raise ConfigError(errors)
    if not data:
        return None, warnings
    layer = Layer(
        name="env",
        source=_ENV_LAYER_SOURCE,
        data=data,
        key_sources=MappingProxyType(sources),
    )
    return layer, warnings
