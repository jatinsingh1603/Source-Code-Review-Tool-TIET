"""The pinned-version manifest of the external engines (E14-01).

Owning epic: E14.

``data/manifest.toml`` holds, per engine id, the pinned and minimum version, an optional container
image pinned by digest, the SPDX licence, how the engine is distributed, whether it may run in a
hosted deployment, whether its licence allows scanning proprietary code, its scheduling weight and
timeout, and the documented telemetry opt-outs. The file is TOML rather than YAML so that no YAML
parser becomes a runtime dependency; the keys are the ones E14-01 lists.

A row in the manifest takes precedence over the same facts in an adapter's ``EngineSpec``, so a
licence correction is a data change, not a code change.
"""

import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Final

from codekavach.analysis.engines.base import (
    ENGINE_ID_PATTERN,
    MAX_WEIGHT,
    DistributionMode,
    EngineSpec,
)

MANIFEST_PATH: Final = Path(__file__).parent / "data" / "manifest.toml"
MAX_MANIFEST_BYTES: Final = 256 * 1024
UNPINNED: Final = "unpinned"
_VERSION: Final = re.compile(r"^[0-9][0-9A-Za-z.+_-]{0,63}$")
_IMAGE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./_:-]{0,200}@sha256:[0-9a-f]{64}$")
_ENV_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_REQUIRED: Final = (
    "pinned_version",
    "min_version",
    "spdx_licence",
    "distribution",
    "hosted_allowed",
    "scans_proprietary_code",
    "install",
)
_KNOWN: Final = frozenset(
    {
        *_REQUIRED,
        "image",
        "signature",
        "weight",
        "timeout_seconds",
        "notes",
        "telemetry_env",
        "telemetry_args",
        "no_documented_opt_out",
    }
)


class ManifestError(ValueError):
    """The manifest is malformed; the message names the engine and the key."""


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One engine's row."""

    engine_id: str
    pinned_version: str
    min_version: str
    spdx_licence: str
    distribution: DistributionMode
    hosted_allowed: bool
    scans_proprietary_code: bool
    install: str
    image: str | None = None
    signature: str | None = None
    weight: int | None = None
    timeout_seconds: int | None = None
    notes: str = ""
    telemetry_env: Mapping[str, str] = field(default_factory=dict)
    telemetry_args: tuple[str, ...] = ()
    no_documented_opt_out: bool = False


@dataclass(frozen=True, slots=True)
class EnginePolicy:
    """The facts the gates read: the manifest row where there is one, the spec otherwise."""

    engine_id: str
    spdx_licence: str
    distribution: DistributionMode
    hosted_allowed: bool
    scans_proprietary_code: bool
    weight: int
    pinned_version: str
    image: str | None
    telemetry_env: Mapping[str, str]
    telemetry_args: tuple[str, ...]
    timeout_seconds: int | None


@dataclass(frozen=True, slots=True)
class LicenceRow:
    """One row of the report appendix "engines and licences"."""

    engine: str
    version: str
    spdx_licence: str
    distribution: DistributionMode
    hosted_allowed: bool
    scans_proprietary_code: bool


def _fail(engine_id: str, key: str, why: str) -> ManifestError:
    return ManifestError(f"manifest engine {engine_id!r} key {key!r}: {why}")


def _text(engine_id: str, key: str, value: object, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise _fail(engine_id, key, "must be a non-empty string")
    if pattern is not None and not pattern.match(value):
        raise _fail(engine_id, key, "has an invalid form")
    return value


def _flag(engine_id: str, key: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise _fail(engine_id, key, "must be true or false")
    return value


def _int(engine_id: str, key: str, value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise _fail(engine_id, key, f"must be an integer between {low} and {high}")
    return value


def _telemetry(engine_id: str, table: Mapping[str, Any]) -> tuple[dict[str, str], tuple[str, ...]]:
    raw_env = table.get("telemetry_env", {})
    if not isinstance(raw_env, dict):
        raise _fail(engine_id, "telemetry_env", "must be a table")
    env: dict[str, str] = {}
    for name, value in raw_env.items():
        if not _ENV_NAME.match(str(name)) or not isinstance(value, str):
            raise _fail(engine_id, "telemetry_env", "holds an invalid variable")
        env[str(name)] = value
    raw_args = table.get("telemetry_args", [])
    if not isinstance(raw_args, list) or not all(
        isinstance(arg, str) and arg and "\x00" not in arg for arg in raw_args
    ):
        raise _fail(engine_id, "telemetry_args", "must be an array of non-empty strings")
    return env, tuple(raw_args)


def _entry(engine_id: str, table: Mapping[str, Any]) -> ManifestEntry:
    if not ENGINE_ID_PATTERN.match(engine_id):
        raise _fail(engine_id, "id", "must match ^[a-z][a-z0-9-]{0,31}$")
    for key in _REQUIRED:
        if key not in table:
            raise _fail(engine_id, key, "is required")
    unknown = sorted(set(table) - _KNOWN)
    if unknown:
        raise _fail(engine_id, unknown[0], "is not a known key")
    try:
        distribution = DistributionMode(_text(engine_id, "distribution", table["distribution"]))
    except ValueError:
        raise _fail(engine_id, "distribution", "is not a known distribution mode") from None
    env, args = _telemetry(engine_id, table)
    no_opt_out = _flag(
        engine_id, "no_documented_opt_out", table.get("no_documented_opt_out", False)
    )
    if no_opt_out and (env or args):
        raise _fail(engine_id, "no_documented_opt_out", "contradicts the opt-outs listed")
    if not no_opt_out and not (env or args):
        raise _fail(
            engine_id, "telemetry_env", "list a documented opt-out or set no_documented_opt_out"
        )
    image = table.get("image")
    weight = table.get("weight")
    timeout = table.get("timeout_seconds")
    return ManifestEntry(
        engine_id=engine_id,
        pinned_version=_text(engine_id, "pinned_version", table["pinned_version"], _VERSION),
        min_version=_text(engine_id, "min_version", table["min_version"], _VERSION),
        spdx_licence=_text(engine_id, "spdx_licence", table["spdx_licence"]),
        distribution=distribution,
        hosted_allowed=_flag(engine_id, "hosted_allowed", table["hosted_allowed"]),
        scans_proprietary_code=_flag(
            engine_id, "scans_proprietary_code", table["scans_proprietary_code"]
        ),
        install=_text(engine_id, "install", table["install"]),
        image=None if image is None else _text(engine_id, "image", image, _IMAGE),
        signature=(
            None
            if table.get("signature") is None
            else _text(engine_id, "signature", table["signature"])
        ),
        weight=None if weight is None else _int(engine_id, "weight", weight, 1, MAX_WEIGHT),
        timeout_seconds=(
            None if timeout is None else _int(engine_id, "timeout_seconds", timeout, 10, 86_400)
        ),
        notes=str(table.get("notes", "")),
        telemetry_env=env,
        telemetry_args=args,
        no_documented_opt_out=no_opt_out,
    )


def parse_manifest(text: str) -> dict[str, ManifestEntry]:
    """Entries by engine id from manifest text; raises :class:`ManifestError`."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ManifestError(f"manifest is not valid TOML: {error}") from None
    engines = document.get("engines", {})
    if not isinstance(engines, dict):
        raise ManifestError("manifest key 'engines' must be a table")
    unknown = sorted(set(document) - {"engines"})
    if unknown:
        raise ManifestError(f"manifest key {unknown[0]!r} is not a known top-level key")
    result: dict[str, ManifestEntry] = {}
    for engine_id, table in sorted(engines.items()):
        if not isinstance(table, dict):
            raise _fail(str(engine_id), "engines", "each engine must be a table")
        result[str(engine_id)] = _entry(str(engine_id), table)
    return result


def _read(path: Path) -> dict[str, ManifestEntry]:
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest is larger than the size limit")
    return parse_manifest(path.read_text(encoding="utf-8"))


@cache
def _bundled() -> Mapping[str, ManifestEntry]:
    return _read(MANIFEST_PATH)


def load_manifest(path: Path | None = None) -> Mapping[str, ManifestEntry]:
    """The manifest entries by engine id; the bundled file is read once."""
    return _bundled() if path is None else _read(path)


def pin_for(
    engine_id: str, manifest: Mapping[str, ManifestEntry] | None = None
) -> ManifestEntry | None:
    """The pinned row of ``engine_id``, or ``None`` when the manifest has none."""
    entries = load_manifest() if manifest is None else manifest
    return entries.get(engine_id)


def effective_policy(
    spec: EngineSpec, manifest: Mapping[str, ManifestEntry] | None = None
) -> EnginePolicy:
    """The licence, hosting and scheduling facts of ``spec``; the manifest row wins."""
    row = pin_for(spec.id, manifest)
    if row is None:
        return EnginePolicy(
            engine_id=spec.id,
            spdx_licence=spec.spdx_licence,
            distribution=spec.distribution,
            hosted_allowed=spec.hosted_allowed,
            scans_proprietary_code=spec.scans_proprietary_code,
            weight=spec.weight,
            pinned_version=UNPINNED,
            image=None,
            telemetry_env={},
            telemetry_args=(),
            timeout_seconds=None,
        )
    return EnginePolicy(
        engine_id=spec.id,
        spdx_licence=row.spdx_licence,
        distribution=row.distribution,
        hosted_allowed=row.hosted_allowed,
        scans_proprietary_code=row.scans_proprietary_code,
        weight=row.weight if row.weight is not None else spec.weight,
        pinned_version=row.pinned_version,
        image=row.image,
        telemetry_env=row.telemetry_env,
        telemetry_args=row.telemetry_args,
        timeout_seconds=row.timeout_seconds,
    )


def licence_inventory(
    specs: Iterable[EngineSpec] | None = None,
    manifest: Mapping[str, ManifestEntry] | None = None,
) -> list[LicenceRow]:
    """One row per registered engine for the report appendix, sorted by engine id.

    Without ``specs`` the registered adapters of the default registry are used.
    """
    if specs is None:
        from codekavach.analysis.engines.registry import iter_adapters  # noqa: PLC0415 - cycle

        specs = [adapter.spec for adapter in iter_adapters()]
    rows = []
    for spec in specs:
        policy = effective_policy(spec, manifest)
        rows.append(
            LicenceRow(
                engine=spec.id,
                version=policy.pinned_version,
                spdx_licence=policy.spdx_licence,
                distribution=policy.distribution,
                hosted_allowed=policy.hosted_allowed,
                scans_proprietary_code=policy.scans_proprietary_code,
            )
        )
    return sorted(rows, key=lambda row: row.engine)


def version_tuple(text: str) -> tuple[int, ...]:
    """The leading numeric components of a version string; ``"1.2.3-rc1"`` gives ``(1, 2, 3)``."""
    parts: list[int] = []
    for piece in re.split(r"[.+_-]", text.strip().lstrip("vV")):
        match = re.match(r"\d+", piece)
        if match is None:
            break
        parts.append(int(match.group()))
        if match.group() != piece:
            break
    return tuple(parts)
