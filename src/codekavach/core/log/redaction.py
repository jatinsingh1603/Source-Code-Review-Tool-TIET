"""The fail-closed redaction processor of every log event (ADR-0005).

Owning epic: E01.

A safety net, not a licence to log sensitive data: the event-style rules of ADR-0005 still apply.
The processor runs just before the renderer, for structlog events and standard-library records
alike, and builds a new structure (the caller's objects are never mutated):

1. sensitive keys (``password``, ``token``, ``apikey``...) have string values replaced;
2. code-bearing keys (``code``, ``payload``, ``prompt``...) are reduced to their length;
3. every string, including the event text and rendered exceptions, is scrubbed of known secret
   formats (``<redacted:NAME>``, deliberately unlike the privacy layer's placeholders);
4. types and sizes: secret types, bytes, long and multi-line strings are replaced; tracebacks are
   exempt from the size rules but truncated and still scrubbed.

If anything in the redaction step raises, the event is replaced by ``log_event_suppressed``
carrying only its level: an unredacted event is never emitted (I4 style fail closed).

Limits: the processor cannot recognise an arbitrary client identifier or business term; it
protects logs only (payloads are protected by the egress guard, E12).
"""

import re
from collections.abc import Callable, Mapping
from pathlib import PurePath
from types import MappingProxyType
from typing import Any, Final

from structlog.typing import EventDict

SENSITIVE_KEY_PARTS: Final = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "privatekey",
    "vaultkey",
    "salt",
    "signature",
)
CODE_KEYS: Final = frozenset(
    {
        "code",
        "source",
        "snippet",
        "slice",
        "text",
        "payload",
        "content",
        "body",
        "prompt",
        "response",
        "completion",
        "original",
        "mapping",
        "literal",
        "identifier",
    }
)
SAFE_KEY_SUFFIXES: Final = ("_count", "_counts", "_estimate", "_tokens", "_len", "_id", "_ms")
TRACEBACK_KEYS: Final = frozenset({"exception", "stack", "stack_info"})
MAX_STRING_LENGTH: Final = 2048
MAX_LINES: Final = 5
MAX_TRACEBACK_LENGTH: Final = 32768
MAX_DEPTH: Final = 8
REDACTED: Final = "<redacted>"
_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_SECRET_TYPES = {("pydantic.types", "SecretStr"), ("pydantic.types", "SecretBytes")}


class _Rule:
    """A named pattern with optional cheap literal hints checked before the expression runs."""

    def __init__(self, pattern: re.Pattern[str], hints: tuple[str, ...], fold: bool) -> None:
        self.pattern = pattern
        self.hints = hints
        self.fold = fold

    def may_match(self, text: str, folded: str) -> bool:
        if not self.hints:
            return True
        haystack = folded if self.fold else text
        return any(hint in haystack for hint in self.hints)


_RULES: dict[str, _Rule] = {}


def _add(name: str, pattern: str, hints: tuple[str, ...] = (), *, fold: bool = False) -> None:
    flags = re.DOTALL if name == "private_key" else 0
    _RULES[name] = _Rule(re.compile(pattern, flags), hints, fold)


_add("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", ("AKIA", "ASIA"))
_add(
    "github_token",
    r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b",
    ("gh", "github_pat_"),
)
_TAIL = r"(?![A-Za-z0-9_-])"  # keys may end in "-" or "_", where \b would not match
_add("llm_api_key", r"\bsk-[A-Za-z0-9_-]{20,}" + _TAIL, ("sk-",))
_add("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}" + _TAIL, ("AIza",))
_add("xai_api_key", r"\bxai-[A-Za-z0-9]{20,}" + _TAIL, ("xai-",))
_add("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}" + _TAIL, ("xox",))
_add(
    "jwt",
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}" + _TAIL,
    ("eyJ",),
)
_add(
    "private_key",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    ("-----BEGIN",),
)
_add("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}", ("bearer",), fold=True)
_add("basic_auth_url", r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)", ("://",))
_add(
    "assignment",
    r"(?i)\b(?P<keep>(?:password|passwd|secret|token|api[_-]?key)\b\s*[=:]\s*[\"']?)"
    r"[^\s\"',;]{4,}",
    ("password", "passwd", "secret", "token", "api"),
    fold=True,
)
_add(
    "validation_input",
    r"(?s)(?P<keep>input_value=).*?(?=, input_type=)",
    ("input_value=",),
)


def register_pattern(name: str, pattern: re.Pattern[str]) -> None:
    """Add a shared detector pattern (E08, E18); names are unique ``snake_case``.

    Raises:
        ValueError: the name is not snake_case or is already registered.
    """
    if not _NAME.match(name):
        raise ValueError("pattern names are snake_case")
    if name in _RULES:
        raise ValueError(f"pattern {name!r} is already registered")
    _RULES[name] = _Rule(pattern, (), fold=False)


def registered_patterns() -> Mapping[str, re.Pattern[str]]:
    """The current patterns by name (read-only view)."""
    return MappingProxyType({name: rule.pattern for name, rule in _RULES.items()})


def _replacer(name: str) -> Callable[[re.Match[str]], str]:
    def replace(match: re.Match[str]) -> str:
        keep = match.group("keep") if "keep" in match.re.groupindex else ""
        return f"{keep or ''}<redacted:{name}>"

    return replace


def scrub_text(value: str) -> str:
    """Replace every known secret format in ``value``; idempotent."""
    folded = value.lower()
    for name, rule in list(_RULES.items()):
        if rule.may_match(value, folded):
            value = rule.pattern.sub(_replacer(name), value)
            folded = value.lower()
    return value


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    if lowered.endswith(SAFE_KEY_SUFFIXES):
        return False
    normalised = lowered.replace("_", "").replace("-", "")
    return any(part in normalised for part in SENSITIVE_KEY_PARTS)


def _line_count(text: str) -> int:
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _text(value: str, traceback: bool) -> str:
    if traceback:
        if len(value) > MAX_TRACEBACK_LENGTH:
            value = value[:MAX_TRACEBACK_LENGTH] + "<truncated>"
        return scrub_text(value)
    if len(value) > MAX_STRING_LENGTH:
        return f"<str:len={len(value)}>"
    lines = _line_count(value)
    if lines > MAX_LINES:
        return f"<text:lines={lines}>"
    return scrub_text(value)


def _size(value: object) -> int:
    try:
        return len(value)  # type: ignore[arg-type]
    except TypeError:
        return 0


def _clean(key: object, value: Any, depth: int, traceback: bool) -> Any:  # noqa: PLR0911, PLR0912
    if depth > MAX_DEPTH:
        return "<nested>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if (type(value).__module__, type(value).__name__) in _SECRET_TYPES:
        return REDACTED
    if isinstance(key, str):
        if _is_sensitive(key) and isinstance(value, (str, bytes, bytearray)):
            return REDACTED
        if key.lower() in CODE_KEYS:
            if isinstance(value, (str, bytes, bytearray)):
                return f"<code:len={len(value)}>"
            return f"<code:items={_size(value)}>"
    if isinstance(value, (bytes, bytearray)):
        return f"<bytes:len={len(value)}>"
    if isinstance(value, PurePath):
        return value
    if isinstance(value, str):
        return _text(value, traceback)
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for name, item in value.items():
            label = name if isinstance(name, str) else scrub_text(str(name))
            cleaned[label] = _clean(label, item, depth + 1, traceback)
        return cleaned
    if isinstance(value, (list, tuple)):
        items = [_clean(None, item, depth + 1, traceback) for item in value]
        return tuple(items) if isinstance(value, tuple) else items
    if isinstance(value, (set, frozenset)):
        return [_clean(None, item, depth + 1, traceback) for item in value]
    if isinstance(value, BaseException):
        return _text(str(value), traceback)
    text = repr(value)
    if len(text) > MAX_STRING_LENGTH:
        return f"<str:len={len(text)}>"
    return _text(text, traceback)


class RedactionProcessor:
    """The structlog processor in the redaction slot of ``codekavach.core.log.config``."""

    def __call__(self, logger: object, method_name: str, event_dict: EventDict) -> EventDict:
        """Return a scrubbed copy of ``event_dict``, or a suppression notice on any error."""
        try:
            return self._redact(event_dict)
        except Exception:  # noqa: BLE001 - fail closed: never emit an unredacted event
            level = event_dict.get("level", method_name)
            return {
                "event": "log_event_suppressed",
                "reason": "redaction_error",
                "level": level if isinstance(level, str) else method_name,
            }

    def _redact(self, event_dict: EventDict) -> EventDict:
        redacted: EventDict = {}
        for key, value in event_dict.items():
            raw: object = key  # standard-library records may carry non-string keys
            label = raw if isinstance(raw, str) else scrub_text(str(raw))
            redacted[label] = _clean(label, value, 0, label in TRACEBACK_KEYS)
        return redacted
