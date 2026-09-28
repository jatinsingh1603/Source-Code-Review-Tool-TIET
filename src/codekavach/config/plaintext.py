"""Refuse plaintext secrets in every configuration layer (CK-CFG-010).

Owning epic: E03.

Every string leaf of a layer is checked before validation:

- rule A: the last key segment looks like a secret name (``api_key``, ``token``, ``password``...)
  and the value is a non-empty string that is not a secret reference;
- rule B: the value has the shape of a known credential, under any key;
- rule C: a long, high-entropy string without whitespace inside a free-form table (for example
  ``llm.providers.*.options``); typed fields are exempt, so model names, globs and hashes cannot
  trigger it.

Messages name the detector, the length, the source, the line and the dotted key, never any
character of the value (CWE-532). There is no bypass switch (ADR decision D8): a false positive is
fixed by moving the value behind a reference or renaming the key. The detectors are deliberately
independent of ``codekavach.privacy.detect`` because the config package is a leaf.
"""

import math
import re
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from codekavach.config.errors import ConfigErrorCode, ConfigIssue
from codekavach.config.introspect import resolve_field
from codekavach.config.keys import DEFAULT_KEY_ENV, is_secret_ref
from codekavach.config.models.root import Settings
from codekavach.config.toml_source import locate_key

SECRET_KEY_NAME = re.compile(
    r"(^|_)(api_?key|apikey|access_?key|secret|token|password|passwd|passphrase|private_?key"
    r"|client_?secret|credential|credentials|auth)($|_)",
    re.IGNORECASE,
)
HIGH_ENTROPY_MIN_LENGTH = 32
HIGH_ENTROPY_MIN_BITS = 4.0
_PATH_START = re.compile(r"^(/|\./|~|[A-Za-z]:)")


@dataclass(frozen=True, slots=True)
class ValueDetector:
    """A credential shape recognised under any key."""

    id: str
    pattern: re.Pattern[str]


VALUE_DETECTORS: tuple[ValueDetector, ...] = (
    ValueDetector("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ValueDetector("openai-key", re.compile(r"sk-(proj-)?[A-Za-z0-9_-]{20,}")),
    ValueDetector("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ValueDetector("xai-key", re.compile(r"xai-[A-Za-z0-9]{20,}")),
    ValueDetector("aws-access-key-id", re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}")),
    ValueDetector(
        "github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}")
    ),
    ValueDetector(
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    ValueDetector("pem-private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ValueDetector("url-credentials", re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")),
)


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(count / total * math.log2(count / total) for count in counts.values())


def _leaves(data: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(data, Mapping):
        for key, value in data.items():
            yield from _leaves(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(data, list | tuple):
        for index, value in enumerate(data):
            yield from _leaves(value, f"{prefix}[{index}]")
    else:
        yield prefix, data


def _settings_key(key: str) -> str:
    """The settings key a raw layer key refers to; profile overlays map to their target."""
    parts = key.split(".")
    if parts[0] == "profiles" and len(parts) > 2:
        return ".".join(parts[2:])
    return key


def _free_form(key: str) -> bool:
    ref = resolve_field(Settings, _settings_key(key))
    return ref is not None and ref.is_mapping_entry


def _shape(value: str) -> str | None:
    for detector in VALUE_DETECTORS:
        if detector.pattern.search(value):
            return detector.id
    return None


def _high_entropy(value: str) -> bool:
    return (
        len(value) >= HIGH_ENTROPY_MIN_LENGTH
        and not any(char.isspace() for char in value)
        and "://" not in value
        and not _PATH_START.match(value)
        and shannon_entropy(value) >= HIGH_ENTROPY_MIN_BITS
    )


def _detect(key: str, value: str) -> str | None:
    last = re.sub(r"\[\d+\]$", "", key.rsplit(".", maxsplit=1)[-1])
    shape = _shape(value)
    if SECRET_KEY_NAME.search(last):
        return shape or "secret-key-name"
    if shape:
        return shape
    if _free_form(key) and _high_entropy(value):
        return "high-entropy"
    return None


def _provider_of(data: Mapping[str, Any], key: str) -> tuple[str | None, str | None]:
    parts = _settings_key(key).split(".")
    if len(parts) >= 3 and parts[0] == "llm" and parts[1] == "providers":
        provider_id = parts[2]
        node: Any = data
        prefix = key.split(".")[: len(key.split(".")) - len(parts)]
        for part in [*prefix, "llm", "providers", provider_id]:
            node = node.get(part, {}) if isinstance(node, Mapping) else {}
        kind = node.get("kind") if isinstance(node, Mapping) else None
        return provider_id, kind if isinstance(kind, str) else None
    return None, None


def _hint(data: Mapping[str, Any], key: str) -> str:
    provider_id, kind = _provider_of(data, key)
    name = provider_id or re.sub(r"\[\d+\]$", "", key.rsplit(".", maxsplit=1)[-1])
    defaults = DEFAULT_KEY_ENV.get(kind or "", ())
    variable = defaults[0] if defaults else f"{name.upper()}_API_KEY"
    return (
        "remove the value from the file and rotate the key if this file was ever committed or "
        "shared.\n"
        # pragma: allowlist nextline secret
        f'Provide it as an environment variable and reference it:  api_key = "env:{variable}"\n'
        f"or store it in the OS keyring:  codekavach config key set {name}"
    )


def find_plaintext_secrets(
    data: Mapping[str, Any],
    *,
    source: str,
    text: str | None,
    key_sources: Mapping[str, str] | None = None,
) -> list[ConfigIssue]:
    """One CK-CFG-010 issue per plaintext secret in ``data``; values are never included."""
    issues: list[ConfigIssue] = []
    for key, value in _leaves(data):
        if not isinstance(value, str) or not value or is_secret_ref(value):
            continue
        detector = _detect(key, value)
        if detector is None:
            continue
        issues.append(
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_010,
                severity="error",
                message=(
                    f"plaintext secret in configuration (detector: {detector}, "
                    f"{len(value)} characters)"
                ),
                key=key,
                source=(key_sources or {}).get(key, source),
                line=locate_key(text, key) if text is not None else None,
                hint=_hint(data, key),
            )
        )
    return issues
