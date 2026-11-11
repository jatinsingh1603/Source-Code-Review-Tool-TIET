"""Builders for rule files, packs and licence directories in tests (E16-01)."""

import copy
from pathlib import Path
from typing import Any

import yaml

BASE_RULE: dict[str, Any] = {
    "id": "python.sqli.cursor-execute-concat",
    "languages": ["python"],
    "message": "SQL query built by string concatenation",
    "severity": "high",
    "confidence": "medium",
    "metadata": {"cwe": [89], "owasp": ["A03:2021"], "licence": "MIT", "added_in": "0.1.0"},
    "match": {
        "any": [
            {
                "pattern": "$CUR.execute($Q)",
                "where": [{"metavariable": "$Q", "kind": "concatenation"}],
            }
        ],
        "none": [{"pattern": "$CUR.execute($Q, $PARAMS)"}],
    },
}


def rule_data(**changes: Any) -> dict[str, Any]:
    """A valid rule as plain data; ``changes`` replace top-level keys."""
    data = copy.deepcopy(BASE_RULE)
    data.update(changes)
    return data


def rule_text(**changes: Any) -> str:
    """A valid rule as YAML text."""
    return yaml.safe_dump(rule_data(**changes), sort_keys=False)


def write_pack(
    base: Path,
    *,
    licence: str = "mit",
    pack: str = "default",
    rules: dict[str, str] | None = None,
    version: str = "1.0.0",
    catalogues: dict[str, str] | None = None,
) -> Path:
    """Write ``base/<licence>/packs/<pack>`` with ``rules`` (name -> text); returns the pack."""
    directory = base / licence / "packs" / pack
    directory.mkdir(parents=True, exist_ok=True)
    spdx = licence.upper() if licence == "mit" else licence
    manifest = {"id": pack, "version": version, "licence": spdx}
    (directory / "pack.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    chosen = rules if rules is not None else {"a/one.yaml": rule_text()}
    for name, text in chosen.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
    for name, text in (catalogues or {}).items():
        target = base / licence / "catalogues" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return directory
