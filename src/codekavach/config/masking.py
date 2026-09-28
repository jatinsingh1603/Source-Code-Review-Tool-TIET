"""Masking of sensitive settings values for every output path (E03-20).

Owning epic: E03.

Rules, applied to every leaf:

1. keys marked ``x-ck-sensitive`` (``privacy.domain_terms``): a non-empty list becomes
   ``["<N hidden>"]`` and a non-empty string becomes ``MASK``; ``reveal_domain_terms=True`` lifts
   this for ``privacy.domain_terms`` only, and the caller warns the user;
2. a string with the shape of a credential (``plaintext.VALUE_DETECTORS``, plus Slack tokens and
   bearer headers), under any key, becomes ``MASK``;
3. user information (the part before ``@`` in the authority) is removed from URLs, so a URL
   carrying credentials is shown as ``https://host/v1``;
4. secret references (``env:NAME``) are names, not secrets, and are shown as they are.

The functions are pure: the input is not mutated, new containers are returned, keys are neither
renamed nor removed, ``None`` and non-string leaves are kept.
"""

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from codekavach.config.introspect import has_marker
from codekavach.config.keys import is_secret_ref
from codekavach.config.models.root import Settings
from codekavach.config.plaintext import VALUE_DETECTORS

MASK = "********"
DOMAIN_TERMS_KEY = "privacy.domain_terms"

# Output-only shapes on top of the loader's detectors: masking is defence in depth, so it also
# covers credentials that have no business in configuration at all.
_EXTRA_SHAPES = (
    re.compile(r"xox[abposr]-[0-9A-Za-z-]{10,}"),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
)
_SHAPES = (*(detector.pattern for detector in VALUE_DETECTORS), *_EXTRA_SHAPES)


def _settings_key(key: str) -> str:
    """The settings key a raw layer key refers to; profile overlays map to their target."""
    parts = key.split(".")
    if parts[0] == "profiles" and len(parts) > 2:
        return ".".join(parts[2:])
    return key


def _without_userinfo(value: str) -> str | None:
    """``value`` with URL user information removed, or ``None`` when it cannot be parsed."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if "@" not in parts.netloc:
        return value
    return urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))


def _mask_string(value: str) -> str:
    if is_secret_ref(value):
        return value
    if "://" in value:
        stripped = _without_userinfo(value)
        if stripped is None:
            return MASK
        value = stripped
    if any(pattern.search(value) for pattern in _SHAPES):
        return MASK
    return value


def _hide(value: Any) -> Any:
    if isinstance(value, list | tuple):
        return [f"<{len(value)} hidden>"] if value else []
    if isinstance(value, str):
        return MASK if value else value
    if isinstance(value, Mapping):
        return {str(key): _hide(item) for key, item in value.items()}
    return value


def _mask(value: Any, key: str, reveal_domain_terms: bool) -> Any:
    if key:
        settings_key = _settings_key(key)
        if has_marker(Settings, settings_key, "sensitive") and not (
            reveal_domain_terms and settings_key == DOMAIN_TERMS_KEY
        ):
            return _hide(value)
    if isinstance(value, Mapping):
        return {
            str(name): _mask(item, f"{key}.{name}" if key else str(name), reveal_domain_terms)
            for name, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [
            _mask(item, f"{key}[{index}]" if key else "", reveal_domain_terms)
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        return _mask_string(value)
    return value


def mask_layer_data(
    data: Mapping[str, Any], *, reveal_domain_terms: bool = False
) -> dict[str, Any]:
    """Mask the raw data of one layer, which may not validate; see the module docstring."""
    masked: dict[str, Any] = _mask(data, "", reveal_domain_terms)
    return masked


def mask_settings(settings: Settings, *, reveal_domain_terms: bool = False) -> dict[str, Any]:
    """A JSON-serialisable dictionary of ``settings`` with every sensitive value masked.

    Every consumer that prints, serialises or transmits settings (``config show``, the
    reproducibility snapshot, reports, the API) must go through this function.
    """
    return mask_layer_data(
        settings.model_dump(mode="json"), reveal_domain_terms=reveal_domain_terms
    )
