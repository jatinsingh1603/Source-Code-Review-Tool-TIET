"""A local MCP server over stdio (newline-delimited JSON-RPC 2.0).

Owning epic: E35.

Tools: ``scan``, ``list_findings``, ``get_finding`` and ``privacy_summary``. The server talks to a
coding assistant that may itself send what it reads to a model, so it exposes less than the CLI:
no vault data and no ``privacy inspect`` output ever; evidence code lines only when the operator
sets ``CODEKAVACH_MCP_INCLUDE_CODE=1`` (and then secret-looking tokens are still masked).
``scan`` runs the local CLI as a child process; with a remote provider the usual consent gate of
the CLI applies. Run it with ``python -m codekavach.integrations.mcp.server``.
"""

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, TextIO

from codekavach.integrations.github.findings import SEVERITIES, mask_text

PROTOCOL_VERSION: Final = "2024-11-05"
SERVER_INFO: Final = {"name": "codekavach", "version": "0.1.0"}
INCLUDE_CODE_ENV: Final = "CODEKAVACH_MCP_INCLUDE_CODE"
_PATH: Final = {"type": "string", "description": "Project directory (default: current directory)."}

TOOLS: Final[list[dict[str, Any]]] = [
    {
        "name": "scan",
        "description": "Scan a project with CodeKavach and return a severity summary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH,
                "privacy_level": {"type": "string", "enum": ["L0", "L1", "L2", "L3", "L4"]},
                "provider": {
                    "type": "string",
                    "description": "LLM provider id; omit for deterministic analysis only.",
                },
            },
        },
    },
    {
        "name": "list_findings",
        "description": "List the findings of the latest scan (no code, metadata only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH,
                "min_severity": {"type": "string", "enum": list(SEVERITIES)},
                "status": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
        },
    },
    {
        "name": "get_finding",
        "description": "Details of one finding: description, remediation, taxonomy, location.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": _PATH, "id": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "privacy_summary",
        "description": "What was sent to LLM providers: counts and ledger integrity, no content.",
        "inputSchema": {"type": "object", "properties": {"path": _PATH}},
    },
]


class ToolError(Exception):
    """A tool failed in a way the model should see."""


def _cli(args: list[str], cwd: str) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, "-m", "codekavach", "--json", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    try:
        envelope: dict[str, Any] = json.loads(done.stdout)
    except ValueError:
        raise ToolError(f"codekavach failed: {done.stderr.strip()[:300]}") from None
    if envelope.get("errors") and "data" not in envelope:
        raise ToolError(str(envelope["errors"][0].get("message")))
    return envelope


def _project(arguments: dict[str, Any]) -> str:
    path = Path(str(arguments.get("path") or ".")).resolve()
    if not path.is_dir():
        raise ToolError(f"not a directory: {path}")
    return str(path)


def _brief(finding: dict[str, Any]) -> dict[str, Any]:
    loc = (finding.get("locations") or [{}])[0]
    return {
        "id": finding["id"],
        "title": mask_text(finding["title"]),
        "severity": finding["severity"],
        "status": finding["status"],
        "cwe": finding.get("cwe", []),
        "path": loc.get("path"),
        "line": loc.get("start_line"),
    }


def _findings(arguments: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    project = _project(arguments)
    envelope = _cli(["findings", project], project)
    if not envelope.get("ok"):
        raise ToolError("no stored scan: run the scan tool first")
    return project, list(envelope["data"]["findings"])


def tool_scan(arguments: dict[str, Any]) -> Any:
    """Run a scan and return counts."""
    project = _project(arguments)
    args = ["scan", project, "--fail-on", "critical"]
    if arguments.get("privacy_level"):
        args += ["--privacy-level", str(arguments["privacy_level"])]
    if arguments.get("provider"):
        args += ["--provider", str(arguments["provider"])]
    else:
        args.append("--no-llm")
    data = _cli(args, project).get("data") or {}
    return {
        "scan_id": data.get("scan_id"),
        "summary": data.get("summary"),
        "privacy_level": data.get("privacy_level"),
        "egress": data.get("egress"),
    }


def tool_list_findings(arguments: dict[str, Any]) -> Any:
    """List findings, most severe first."""
    _, findings = _findings(arguments)
    floor = SEVERITIES.index(str(arguments.get("min_severity") or "info"))
    status = arguments.get("status")
    chosen = [
        f
        for f in findings
        if SEVERITIES.index(f["severity"]) >= floor and (not status or f["status"] == status)
    ]
    chosen.sort(key=lambda f: -SEVERITIES.index(f["severity"]))
    limit = int(arguments.get("limit") or 50)
    return {"total": len(chosen), "findings": [_brief(f) for f in chosen[:limit]]}


def tool_get_finding(arguments: dict[str, Any]) -> Any:
    """One finding in detail; code lines only when the operator allowed them."""
    _, findings = _findings(arguments)
    wanted = str(arguments.get("id"))
    found = next((f for f in findings if wanted in (f["id"], f["fingerprint"])), None)
    if found is None:
        raise ToolError(f"no finding {wanted}")
    detail = {
        **_brief(found),
        "description": mask_text(found.get("description", "")),
        "remediation": mask_text(found.get("remediation", "")),
        "owasp": [r.get("id") for r in found.get("owasp", [])],
        "confidence": found.get("confidence"),
        "rule": ((found.get("provenance") or {}).get("engines") or [{}])[0].get("rule_id"),
        "fingerprint": found["fingerprint"],
    }
    if os.environ.get(INCLUDE_CODE_ENV) == "1":
        lines = ((found.get("evidence") or [{}])[0]).get("lines", [])
        detail["code"] = [{"line": x["number"], "text": mask_text(x["text"])} for x in lines]
    else:
        detail["code"] = f"withheld; set {INCLUDE_CODE_ENV}=1 on the server to include it"
    return detail


def tool_privacy_summary(arguments: dict[str, Any]) -> Any:
    """Ledger counts and integrity; never payload text."""
    project = _project(arguments)
    shown = _cli(["privacy", "ledger", "show"], project).get("data") or {}
    checked = _cli(["privacy", "ledger", "verify"], project).get("data") or {}
    return {
        "payloads_sent": shown.get("total", 0),
        "chain_ok": (checked.get("chain") or {}).get("ok"),
        "payload_mismatches": len((checked.get("payloads") or {}).get("mismatched", [])),
        "note": "content is never returned by this server",
    }


HANDLERS: Final[dict[str, Callable[[dict[str, Any]], Any]]] = {
    "scan": tool_scan,
    "list_findings": tool_list_findings,
    "get_finding": tool_get_finding,
    "privacy_summary": tool_privacy_summary,
}


def handle(message: dict[str, Any]) -> dict[str, Any] | None:  # noqa: PLR0911 - one branch per method
    """Answer one JSON-RPC message; ``None`` for a notification."""
    method = message.get("method")
    ident = message.get("id")
    if ident is None:
        return None  # notifications/initialized and friends need no answer

    def ok(result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": ident, "result": result}

    def fail(code: int, text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": ident, "error": {"code": code, "message": text}}

    if method == "initialize":
        return ok(
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            }
        )
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        params = message.get("params") or {}
        handler = HANDLERS.get(str(params.get("name")))
        if handler is None:
            return fail(-32602, f"unknown tool {params.get('name')}")
        try:
            result = handler(params.get("arguments") or {})
            text, is_error = json.dumps(result, indent=1), False
        except ToolError as error:
            text, is_error = str(error), True
        return ok({"content": [{"type": "text", "text": text}], "isError": is_error})
    return fail(-32601, f"method not found: {method}")


def serve(stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
    """Read one JSON message per line until end of input."""
    for line in stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            reply = handle(message)
        except ValueError:
            reply = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "parse error"},
            }
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def main() -> None:
    """Entry point: ``codekavach-mcp`` or ``python -m codekavach.integrations.mcp.server``."""
    serve()


if __name__ == "__main__":
    main()
