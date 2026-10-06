"""JSON Schemas of ``codekavach.toml`` and ``policy.toml`` for editors and validation (E03-38).

Owning epic: E03.

``settings_schema()`` and ``policy_schema()`` export the validation-mode schemas of ``Settings``
and ``OrgPolicy``, post-processed: ``$schema`` (draft 2020-12), ``$id`` (``SCHEMA_ID`` and
``POLICY_SCHEMA_ID``), a title and a description; every property has a description; the
``x-ck-*`` extension keywords are kept; and ``profiles.*`` accepts a partial settings document
(the same sections, nothing required, plus ``extends`` and ``description``). ``dump_schema`` writes
sorted keys with a two-space indent, so the committed files in ``docs/schemas/`` are reproducible
(``codekavach config schema``); ``tests/unit/config/test_schema_drift.py`` fails when they are
stale. The ``$id`` is an identifier; nothing fetches it.
"""

import copy
import json
from typing import Any

from codekavach.config.constants import POLICY_SCHEMA_ID, SCHEMA_ID
from codekavach.config.models.root import Settings
from codekavach.config.orgpolicy.model import OrgPolicy

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SETTINGS_FILE = "codekavach.schema.json"
POLICY_FILE = "codekavach-policy.schema.json"
PARTIAL_SETTINGS = "PartialSettings"
# Root keys that are not settings and therefore not part of a profile overlay.
_NOT_IN_PROFILES = frozenset({"config_version", "profile", "profiles"})


def _definition(schema: dict[str, Any], ref: str) -> dict[str, Any] | None:
    if not ref.startswith("#/$defs/"):
        return None
    found = schema.get("$defs", {}).get(ref.removeprefix("#/$defs/"))
    return found if isinstance(found, dict) else None


def _fill_descriptions(node: Any, root: dict[str, Any]) -> None:
    """Give every property a description, taking it from the referenced definition if needed.

    Pydantic drops a field's description when it equals the docstring of the model it refers to.
    """
    if isinstance(node, dict):
        for value in (node.get("properties") or {}).values():
            if isinstance(value, dict) and not value.get("description") and "$ref" in value:
                target = _definition(root, value["$ref"])
                if target is not None and target.get("description"):
                    value["description"] = target["description"]
        for value in node.values():
            _fill_descriptions(value, root)
    elif isinstance(node, list):
        for item in node:
            _fill_descriptions(item, root)


def _partial_settings(schema: dict[str, Any]) -> dict[str, Any]:
    properties = {
        name: copy.deepcopy(value)
        for name, value in schema["properties"].items()
        if name not in _NOT_IN_PROFILES
    }
    properties["extends"] = {
        "description": "Name of the profile this profile builds on.",
        "type": "string",
    }
    properties["description"] = {
        "description": "One line saying what the profile is for.",
        "type": "string",
    }
    return {
        "additionalProperties": False,
        "description": "A profile overlay: any settings sections, all optional.",
        "properties": properties,
        "title": PARTIAL_SETTINGS,
        "type": "object",
    }


def _finish(schema: dict[str, Any], schema_id: str, title: str, description: str) -> None:
    schema["$schema"] = JSON_SCHEMA_DIALECT
    schema["$id"] = schema_id
    schema["title"] = title
    schema["description"] = description
    _fill_descriptions(schema, schema)


def settings_schema() -> dict[str, Any]:
    """The JSON Schema of ``codekavach.toml`` (the ``Settings`` model)."""
    schema = Settings.model_json_schema(mode="validation")
    schema.setdefault("$defs", {})[PARTIAL_SETTINGS] = _partial_settings(schema)
    profiles = schema["properties"]["profiles"]
    profiles["additionalProperties"] = {"$ref": f"#/$defs/{PARTIAL_SETTINGS}"}
    _finish(
        schema,
        SCHEMA_ID,
        "CodeKavach configuration",
        "Settings of codekavach.toml and the user configuration file (ADR-0006).",
    )
    return schema


def policy_schema() -> dict[str, Any]:
    """The JSON Schema of an organisation ``policy.toml`` (the ``OrgPolicy`` model)."""
    schema = OrgPolicy.model_json_schema(mode="validation")
    _finish(
        schema,
        POLICY_SCHEMA_ID,
        "CodeKavach organisation policy",
        "Floors, allow-lists and locks an organisation imposes on every run (ADR-0006 D7).",
    )
    return schema


def dump_schema(schema: dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, two-space indent, UTF-8 text, a trailing newline."""
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
