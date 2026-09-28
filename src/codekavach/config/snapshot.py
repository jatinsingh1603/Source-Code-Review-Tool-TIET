"""Effective-configuration snapshot and settings fingerprint, for reproducibility (E03-39).

Owning epic: E03.

``settings_fingerprint`` is a SHA-256 over the settings that can change findings, payloads or
verdicts (I5, R11): the pipeline cache, resumed scans and experiment records compare it.
Excluded: every ``x-ck-volatile`` field (parallelism, time-outs, retries, caching) and secret
references (rotating a key must not invalidate caches). Sensitive fields (domain terms) enter
only as a keyed digest, so the fingerprint changes with them while nothing stores them.
Union-merged lists are sorted first, because their order reflects layer order, not meaning.

Stability contract: the format is versioned by the prefix ``ck-fp-v1``. Changing which fields
are included requires a new prefix and a CHANGELOG entry.

``EffectiveConfigSnapshot`` records the masked effective configuration with its provenance. It
never contains vault material, the scan salt, resolved secrets, secret references or sensitive
terms (I3), so it can be attached to reports and experiment archives.
"""

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from codekavach.config.introspect import has_marker, keys_with_marker
from codekavach.config.masking import mask_settings
from codekavach.config.merge import is_union_key
from codekavach.config.models.root import Settings
from codekavach.config.plaintext import SECRET_KEY_NAME

if TYPE_CHECKING:
    from codekavach.config.loader import LoadedConfig

FINGERPRINT_PREFIX = b"ck-fp-v1"
DEFAULT_SECTIONS: tuple[str, ...] = ("project.languages", "scan", "engines", "privacy", "llm")
SECRET_REFERENCE_FIELDS = frozenset({"api_key", "token", "passphrase"})
_DROP = object()
_INDEX = re.compile(r"\[\d+\]$")


def _plain(value: Any) -> Any:
    """``value`` as JSON-ready data: POSIX paths, enum values, ISO dates, string keys."""
    if isinstance(value, BaseModel):
        return _plain(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        return {_plain_key(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_plain(item) for item in value]
    if isinstance(value, Enum):
        return _plain(value.value)
    return _plain_leaf(value)


def _plain_leaf(value: Any) -> Any:
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, datetime | date):
        return value.isoformat()
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return str(value)


def _plain_key(key: Any) -> str:
    return str(key.value) if isinstance(key, Enum) else str(key)


def canonical_json(data: Any) -> bytes:
    """Sorted keys, no spaces, ASCII only, POSIX paths, enum values, floats as ``repr``."""
    return json.dumps(
        _plain(data), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(FINGERPRINT_PREFIX + canonical_json(value)).hexdigest()


def _prepare(value: Any, key: str, union_keys: frozenset[str]) -> Any:
    """``value`` of ``key`` as it enters the fingerprint, or ``_DROP``."""
    last = _INDEX.sub("", key.rsplit(".", maxsplit=1)[-1])
    if last in SECRET_REFERENCE_FIELDS or has_marker(Settings, key, "volatile"):
        return _DROP
    if isinstance(value, list) and is_union_key(key, union_keys):
        value = sorted(value, key=canonical_json)
    if has_marker(Settings, key, "sensitive"):
        return _digest(value)
    if isinstance(value, Mapping):
        prepared = {
            name: _prepare(item, f"{key}.{name}", union_keys) for name, item in value.items()
        }
        return {name: item for name, item in prepared.items() if item is not _DROP}
    if isinstance(value, list):
        return [_prepare(item, f"{key}[{index}]", union_keys) for index, item in enumerate(value)]
    return value


def _get(data: Mapping[str, Any], key: str) -> Any:
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _DROP
        node = node[part]
    return node


def settings_fingerprint(settings: Settings, *, sections: Sequence[str] = DEFAULT_SECTIONS) -> str:
    """A stable SHA-256 over the result-affecting settings of ``sections`` (hex)."""
    data = _plain(settings)
    union_keys = keys_with_marker(Settings, "union")
    selected: dict[str, Any] = {}
    for section in sections:
        value = _get(data, section)
        if value is _DROP:
            continue
        prepared = _prepare(value, section, union_keys)
        if prepared is not _DROP:
            selected[section] = prepared
    return _digest(selected)


def _without_secret_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _without_secret_keys(item)
            for key, item in value.items()
            if not SECRET_KEY_NAME.search(str(key))
        }
    if isinstance(value, list):
        return [_without_secret_keys(item) for item in value]
    return value


class EffectiveConfigSnapshot(BaseModel):
    """The masked effective configuration of one run, with provenance and fingerprint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = Field(default=1, description="Snapshot format version.")
    created_at: datetime = Field(description="When the snapshot was taken (UTC).")
    codekavach_version: str = Field(description="Version of CodeKavach that took it.")
    fingerprint: str = Field(description="settings_fingerprint of the effective settings.")
    profile: str | None = Field(default=None, description="Selected profile, if any.")
    settings: dict[str, Any] = Field(description="Masked effective settings.")
    origins: dict[str, dict[str, Any]] = Field(description="Origin of every settings key.")
    project_trust: str = Field(description="How the project configuration was trusted.")
    org_policies: list[dict[str, Any]] = Field(
        default_factory=list, description="Organisation policies applied."
    )
    warnings: list[dict[str, str | None]] = Field(
        default_factory=list, description="Configuration warnings: codes and keys only."
    )


def build_snapshot(
    loaded: "LoadedConfig", *, codekavach_version: str, now: datetime | None = None
) -> EffectiveConfigSnapshot:
    """The snapshot of ``loaded``: masked, without secret references or sensitive terms."""
    origins = {
        key: {
            "layer": origin.layer,
            "source": origin.source,
            "line": origin.line,
            "contributors": list(origin.contributors),
        }
        for key, origin in sorted(loaded.origins.items())
        if not SECRET_KEY_NAME.search(_INDEX.sub("", key.rsplit(".", maxsplit=1)[-1]))
    }
    return EffectiveConfigSnapshot(
        created_at=(now or datetime.now(UTC)).astimezone(UTC),
        codekavach_version=codekavach_version,
        fingerprint=settings_fingerprint(loaded.settings),
        profile=loaded.profile,
        settings=_without_secret_keys(mask_settings(loaded.settings)),
        origins=origins,
        project_trust=loaded.project_trust,
        org_policies=[
            {
                "organisation": policy.policy.organisation,
                "path": Path(policy.path).as_posix(),
                "sha256": policy.sha256,
                "enforcement": policy.policy.enforcement,
                "signature": policy.signature,
            }
            for policy in loaded.org_policies
        ],
        warnings=[{"code": issue.code.value, "key": issue.key} for issue in loaded.warnings],
    )


def write_snapshot(snapshot: EffectiveConfigSnapshot, path: Path) -> None:
    """Write the snapshot as indented JSON with sorted keys."""
    text = json.dumps(snapshot.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def read_snapshot(path: Path) -> EffectiveConfigSnapshot:
    """Read a snapshot written by ``write_snapshot``."""
    return EffectiveConfigSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
