"""The TOML tables behind CWE fallback and severity normalisation (E14-02).

Owning epic: E14. The tables are TOML rather than YAML so that no YAML parser becomes a runtime
dependency. A broken table is a packaging error, so loading raises ``TableError`` with the key and
never with the file's content.
"""

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Final

from codekavach.core.models.enums import Confidence, Severity

DATA_DIR: Final = Path(__file__).resolve().parents[1] / "data"
CWE_FALLBACK_PATH: Final = DATA_DIR / "cwe_fallback.toml"
SEVERITY_MAP_PATH: Final = DATA_DIR / "severity_map.toml"
_SEVERITY_KEYS = frozenset({"default_level_map", "confidence_keys", "confidence_map", "rules"})


class TableError(ValueError):
    """A data table is malformed."""


def longest_prefix[T](table: Mapping[str, T], key: str) -> T | None:
    """The value of the longest key of ``table`` that ``key`` starts with (an exact one too)."""
    best: str | None = None
    for candidate in table:
        if key.startswith(candidate) and (best is None or len(candidate) > len(best)):
            best = candidate
    return None if best is None else table[best]


@dataclass(frozen=True)
class CweFallback:
    """``engine id -> rule id or prefix -> CWE numbers``."""

    engines: Mapping[str, Mapping[str, tuple[int, ...]]] = field(default_factory=dict)

    def lookup(self, engine_id: str, rule_id: str) -> tuple[int, ...]:
        """The CWE numbers for the exact rule id, else for the longest matching prefix."""
        rows = self.engines.get(engine_id)
        if not rows:
            return ()
        return longest_prefix(rows, rule_id) or ()


@dataclass(frozen=True)
class EngineSeverityRules:
    """What one engine's vocabulary means."""

    level_map: Mapping[str, Severity] = field(default_factory=dict)
    rules: Mapping[str, Severity] = field(default_factory=dict)
    confidence_keys: tuple[str, ...] = ()
    confidence_map: Mapping[str, Confidence] = field(default_factory=dict)


@dataclass(frozen=True)
class SeverityTable:
    """``engine id -> EngineSeverityRules``."""

    engines: Mapping[str, EngineSeverityRules] = field(default_factory=dict)


def _read(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise TableError(f"cannot read table {path.name}: {type(error).__name__}") from None
    engines = data.get("engines", {})
    if not isinstance(engines, dict):
        raise TableError(f"{path.name}: 'engines' must be a table")
    return engines


def parse_cwe_fallback(path: Path) -> CweFallback:
    """Load a CWE fallback table."""
    engines: dict[str, dict[str, tuple[int, ...]]] = {}
    for engine_id, rows in _read(path).items():
        if not isinstance(rows, dict):
            raise TableError(f"engines.{engine_id}: must be a table")
        parsed: dict[str, tuple[int, ...]] = {}
        for rule, value in rows.items():
            numbers = value if isinstance(value, list) else [value]
            if not numbers or not all(
                isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= 99999 for n in numbers
            ):
                raise TableError(f"engines.{engine_id}.{rule}: expected CWE numbers")
            parsed[rule] = tuple(numbers)
        engines[engine_id] = parsed
    return CweFallback(engines)


def _enum_map[E](values: object, where: str, make: type[E]) -> dict[str, E]:
    if not isinstance(values, dict):
        raise TableError(f"{where}: must be a table")
    out: dict[str, E] = {}
    for key, word in values.items():
        try:
            out[str(key)] = make(word)  # type: ignore[call-arg]
        except ValueError:
            raise TableError(f"{where}.{key}: unknown value") from None
    return out


def parse_severity_map(path: Path) -> SeverityTable:
    """Load a severity table."""
    engines: dict[str, EngineSeverityRules] = {}
    for engine_id, row in _read(path).items():
        if not isinstance(row, dict) or not set(row) <= _SEVERITY_KEYS:
            raise TableError(f"engines.{engine_id}: unknown or malformed keys")
        keys = row.get("confidence_keys", [])
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise TableError(f"engines.{engine_id}.confidence_keys: expected strings")
        engines[engine_id] = EngineSeverityRules(
            level_map=_enum_map(
                row.get("default_level_map", {}), f"engines.{engine_id}.level", Severity
            ),
            rules=_enum_map(row.get("rules", {}), f"engines.{engine_id}.rules", Severity),
            confidence_keys=tuple(keys),
            confidence_map={
                k.lower(): v
                for k, v in _enum_map(
                    row.get("confidence_map", {}), f"engines.{engine_id}.confidence_map", Confidence
                ).items()
            },
        )
    return SeverityTable(engines)


@cache
def default_cwe_fallback() -> CweFallback:
    """The shipped CWE fallback table."""
    return parse_cwe_fallback(CWE_FALLBACK_PATH)


@cache
def default_severity_table() -> SeverityTable:
    """The shipped severity table."""
    return parse_severity_map(SEVERITY_MAP_PATH)
