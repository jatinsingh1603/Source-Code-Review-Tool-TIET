"""Builders for SARIF logs and the source trees they point into (E14-02)."""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


def write_tree(root: Path, files: Mapping[str, str]) -> Path:
    """Create ``files`` under ``root`` (the read-only view stand-in) and return it."""
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
    return root


def numbered_source(lines: int = 100, width: int = 80) -> str:
    """A file of ``lines`` lines, each ``width`` characters wide, line 1 first."""
    return (
        "\n".join(f"line {number:04d} ".ljust(width, "x") for number in range(1, lines + 1)) + "\n"
    )


def region(
    start_line: int = 1,
    start_column: int | None = None,
    end_line: int | None = None,
    end_column: int | None = None,
) -> dict[str, Any]:
    """A SARIF region with only the stated members."""
    found: dict[str, Any] = {"startLine": start_line}
    if start_column is not None:
        found["startColumn"] = start_column
    if end_line is not None:
        found["endLine"] = end_line
    if end_column is not None:
        found["endColumn"] = end_column
    return found


def location(
    uri: str,
    *,
    base_id: str | None = None,
    at: dict[str, Any] | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    """A SARIF location for ``uri``."""
    artifact: dict[str, Any] = {"uri": uri}
    if base_id is not None:
        artifact["uriBaseId"] = base_id
    physical: dict[str, Any] = {"artifactLocation": artifact}
    if at is not None:
        physical["region"] = at
    found: dict[str, Any] = {"physicalLocation": physical}
    if message is not None:
        found["message"] = {"text": message}
    return found


def step(uri: str, line: int, text: str | None = None, **extra: Any) -> dict[str, Any]:
    """A thread-flow location."""
    return {"location": location(uri, at=region(line), message=text), **extra}


def code_flow(*steps: dict[str, Any]) -> dict[str, Any]:
    """A code flow with one thread flow."""
    return {"threadFlows": [{"locations": list(steps)}]}


def result(
    rule_id: str = "rule-1",
    *,
    uri: str = "app.py",
    line: int = 1,
    level: str | None = "warning",
    message: str = "finding",
    **extra: Any,
) -> dict[str, Any]:
    """A SARIF result at ``uri:line``."""
    found: dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [location(uri, at=region(line))],
    }
    if level is not None:
        found["level"] = level
    found.update(extra)
    return found


def run(
    results: Sequence[dict[str, Any]],
    *,
    rules: Sequence[dict[str, Any]] = (),
    name: str = "tool",
    version: str | None = "1.0.0",
    **extra: Any,
) -> dict[str, Any]:
    """A SARIF run."""
    driver: dict[str, Any] = {"name": name, "rules": list(rules)}
    if version is not None:
        driver["version"] = version
    return {"tool": {"driver": driver}, "results": list(results), **extra}


def log(*runs: dict[str, Any]) -> bytes:
    """A SARIF 2.1.0 log of ``runs`` as bytes."""
    return json.dumps({"version": "2.1.0", "runs": list(runs)}).encode("utf-8")
