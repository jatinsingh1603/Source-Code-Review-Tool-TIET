"""Load and refuse project privacy policies, with the codes of ``codekavach.privacy.policy.errors``.

Owning epic: E25.

``load_document`` validates text (used by the server's policy page and by tests). ``load_policy``
is what a scan uses: it reads ``codekavach.policy.toml`` from the project root with the safe reader
of the configuration layer (size, encoding, regular file), refuses a symbolic link and a file that
resolves outside the project root, and refuses any level weaker than ``privacy.min_level`` with
``[CK-POL-006]`` rather than clamping it. A refused policy aborts the run (invariant I4): there is
no fallback to a default document.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.errors import ConfigError
from codekavach.config.toml_source import read_toml
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.policy.errors import PolicyError, PolicyErrorCode
from codekavach.privacy.policy.model import MAX_RULES, PolicyDocument

POLICY_FILE: Final = "codekavach.policy.toml"
MAX_DOCUMENT_BYTES: Final = 256 * 1024
_TOML_POSITION: Final = re.compile(r"at line (\d+), column (\d+)")
_AXES: Final = ("path", "language", "rule", "classification")
_TOP: Final = frozenset({"policy_version", "provider_tiers", *_AXES})
_TIERS: Final = frozenset(t.value for t in TrustTier)


def _table_line(text: str, table: str, index: int) -> int | None:
    """The 1-based line of the ``index``-th ``[[table]]`` header, if present."""
    header = re.compile(r"^\s*\[\[\s*" + re.escape(table) + r"\s*\]\]")
    seen = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if header.match(line):
            if seen == index:
                return number
            seen += 1
    return None


def _key_line(text: str, key: str) -> int | None:
    rx = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
    for number, line in enumerate(text.splitlines(), start=1):
        if rx.match(line):
            return number
    return None


def _where(text: str, location: str) -> int | None:
    match = re.match(r"^(\w+)\[(\d+)\]", location)
    if match:
        return _table_line(text, match.group(1), int(match.group(2)))
    return _key_line(text, location.rsplit(".", 1)[-1])


def _precheck(data: dict[str, Any], text: str, file: str | None) -> None:
    version = data.get("policy_version", 1)
    if version != 1:
        raise PolicyError(
            PolicyErrorCode.SCHEMA_VERSION,
            f"policy_version {version!r} is not supported (expected 1)",
            file=file,
            line=_key_line(text, "policy_version"),
        )
    for key in data:
        if key not in _TOP:
            raise PolicyError(
                PolicyErrorCode.UNKNOWN_KEY, f"unknown table or key {key!r}", file=file
            )
    tiers = data.get("provider_tiers", {})
    if isinstance(tiers, dict):
        for tier in tiers:
            if tier not in _TIERS:
                raise PolicyError(
                    PolicyErrorCode.UNKNOWN_TIER,
                    f"provider tier {tier!r} is not one of {sorted(_TIERS)}",
                    file=file,
                    line=_key_line(text, tier),
                )
    total = sum(len(v) for k in _AXES if isinstance(v := data.get(k, []), list))
    if total > MAX_RULES:
        raise PolicyError(
            PolicyErrorCode.TOO_MANY_RULES, f"{total} rules; at most {MAX_RULES}", file=file
        )
    for index, rule in enumerate(data.get("path", []) or []):
        if isinstance(rule, dict) and ("level" in rule) == bool(rule.get("never_send", False)):
            raise PolicyError(
                PolicyErrorCode.LEVEL_AND_NEVER_SEND,
                "a [[path]] rule sets exactly one of level or never_send",
                file=file,
                line=_table_line(text, "path", index),
                pattern=str(rule.get("pattern")),
            )
    for index, rule in enumerate(data.get("classification", []) or []):
        if isinstance(rule, dict) and "level" not in rule and not rule.get("never_send", False):
            raise PolicyError(
                PolicyErrorCode.TAG_WITHOUT_LEVEL,
                f"classification tag {rule.get('tag')!r} sets neither level nor never_send",
                file=file,
                line=_table_line(text, "classification", index),
            )


def _validate(data: dict[str, Any], text: str, file: str | None) -> PolicyDocument:
    _precheck(data, text, file)
    try:
        return PolicyDocument.model_validate(data)
    except PolicyError as error:  # a bad pattern, raised from a field validator
        line = None
        if error.pattern is not None:
            needle = f'"{error.pattern}"'
            line = next(
                (n for n, ln in enumerate(text.splitlines(), start=1) if needle in ln), None
            )
        raise PolicyError(
            error.code,
            str(error).split(": ", 1)[-1],
            file=file,
            line=line,
            pattern=error.pattern,
        ) from None
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise PolicyError(
            PolicyErrorCode.UNKNOWN_KEY,
            f"invalid policy at '{where}': {first['msg']}",
            file=file,
            line=_where(text, where),
        ) from None


def load_document(
    source: str | bytes | Path, *, file: str | None = None
) -> tuple[PolicyDocument, str]:
    """Parse and validate a policy; returns the document and its content hash (sha256 hex).

    The hash is over the file's bytes, so it names exactly the document an operator reviewed.
    """
    if isinstance(source, Path):
        try:
            raw = source.read_bytes()
        except OSError:
            raise PolicyError(
                PolicyErrorCode.UNREADABLE, "policy file cannot be read", file=source
            ) from None
        file = file or source.name
    elif isinstance(source, str):
        raw = source.encode()
    else:
        raw = source
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise PolicyError(PolicyErrorCode.UNREADABLE, "policy document is too large", file=file)
    try:
        text = raw.decode("utf-8")
        data = tomllib.loads(text)
    except UnicodeDecodeError:
        raise PolicyError(
            PolicyErrorCode.UNREADABLE, "policy is not valid UTF-8 text", file=file
        ) from None
    except tomllib.TOMLDecodeError as exc:
        # Only the position is kept: tomllib's own wording can quote a key or a character of
        # the document, and an error message names no file contents.
        at = _TOML_POSITION.search(str(exc))
        raise PolicyError(
            PolicyErrorCode.UNREADABLE,
            "policy is not valid TOML" + (f" (column {at.group(2)})" if at else ""),
            file=file,
            line=int(at.group(1)) if at else None,
        ) from None
    return _validate(data, text, file), sha256_hex(raw)


def check_floor(document: PolicyDocument, settings: Settings, text: str, file: str | None) -> None:
    """Refuse (never clamp) any level weaker than ``privacy.min_level``: ``[CK-POL-006]``."""
    floor = settings.privacy.min_level
    for location, level in document.levels():
        if not level.at_least(floor):
            raise PolicyError(
                PolicyErrorCode.BELOW_MIN_LEVEL,
                f"{location} sets {level.value}, weaker than privacy.min_level {floor.value}",
                file=file,
                line=_where(text, location),
            )


def policy_file(project_root: Path) -> Path:
    """Where a project keeps its policy."""
    return project_root / POLICY_FILE


def load_policy(settings: Settings, *, project_root: Path) -> tuple[PolicyDocument, str] | None:
    """The project's policy and its hash, or ``None`` when the project has none.

    Raises:
        PolicyError: any of ``[CK-POL-001]`` to ``[CK-POL-009]``; nothing is clamped or defaulted.
    """
    path = policy_file(project_root)
    if path.is_symlink():
        raise PolicyError(
            PolicyErrorCode.UNREADABLE, "policy file is a symbolic link", file=POLICY_FILE
        )
    if not path.exists():
        return None
    try:
        document = read_toml(path, max_bytes=MAX_DOCUMENT_BYTES, confine_to=project_root)
    except ConfigError as error:
        raise PolicyError(
            PolicyErrorCode.UNREADABLE, f"policy file refused ({error.code})", file=POLICY_FILE
        ) from None
    loaded = _validate(document.data, document.text, POLICY_FILE)
    check_floor(loaded, settings, document.text, POLICY_FILE)
    return loaded, document.sha256
