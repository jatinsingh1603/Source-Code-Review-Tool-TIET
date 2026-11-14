"""The MCP stdio server: protocol, tool list and what it refuses to expose."""

import io
import json
from typing import Any

import pytest

from codekavach.integrations.mcp import server


def call(message: dict[str, Any]) -> dict[str, Any]:
    reply = server.handle({"jsonrpc": "2.0", **message})
    assert reply is not None
    return reply


def test_initialize_and_list() -> None:
    init = call({"id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "codekavach"
    tools = call({"id": 2, "method": "tools/list"})["result"]["tools"]
    assert {t["name"] for t in tools} == {"scan", "list_findings", "get_finding", "privacy_summary"}
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert call({"id": 3, "method": "nope"})["error"]["code"] == -32601


def test_serve_handles_bad_json() -> None:
    out = io.StringIO()
    server.serve(io.StringIO('not json\n{"jsonrpc":"2.0","id":5,"method":"ping"}\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700 and lines[1]["result"] == {}


FINDING = {
    "id": "find_1",
    "fingerprint": "ckfp1:" + "a" * 32,
    "title": "SQL injection",
    "severity": "high",
    "status": "open",
    "cwe": [89],
    "description": "token = 'abcdefgh12345678'",
    "locations": [{"path": "a.py", "start_line": 3}],
    "evidence": [{"lines": [{"number": 3, "text": "password = 'hunter2hunter2'"}]}],
    "provenance": {"engines": [{"rule_id": "py.sqli"}]},
}


def test_get_finding_withholds_code_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setattr(
        server, "_cli", lambda args, cwd: {"ok": True, "data": {"findings": [FINDING]}}
    )
    monkeypatch.delenv(server.INCLUDE_CODE_ENV, raising=False)
    result = call(
        {
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_finding", "arguments": {"id": "find_1", "path": str(tmp_path)}},
        }
    )["result"]
    text = result["content"][0]["text"]
    assert "withheld" in text and "hunter2" not in text and "abcdefgh12345678" not in text


def test_get_finding_masks_code_when_allowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setattr(
        server, "_cli", lambda args, cwd: {"ok": True, "data": {"findings": [FINDING]}}
    )
    monkeypatch.setenv(server.INCLUDE_CODE_ENV, "1")
    result = call(
        {
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_finding", "arguments": {"id": "find_1", "path": str(tmp_path)}},
        }
    )["result"]
    text = result["content"][0]["text"]
    assert "password" in text and "hunter2hunter2" not in text


def test_list_filters_and_unknown_finding(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    low = {**FINDING, "id": "find_2", "severity": "low"}
    monkeypatch.setattr(
        server, "_cli", lambda args, cwd: {"ok": True, "data": {"findings": [FINDING, low]}}
    )
    args = {"path": str(tmp_path), "min_severity": "high"}
    out = call(
        {"id": 1, "method": "tools/call", "params": {"name": "list_findings", "arguments": args}}
    )
    assert json.loads(out["result"]["content"][0]["text"])["total"] == 1
    miss = call(
        {
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_finding", "arguments": {"id": "zzz", "path": str(tmp_path)}},
        }
    )
    assert miss["result"]["isError"] is True


def test_help_and_version_answer_without_serving(capsys: pytest.CaptureFixture[str]) -> None:
    server.main(["--help"])
    assert "codekavach-mcp" in capsys.readouterr().out
    server.main(["--version"])
    assert capsys.readouterr().out.startswith("codekavach-mcp ")
    with pytest.raises(SystemExit) as info:
        server.main(["--port", "8080"])
    assert info.value.code == 2
    assert "takes no arguments" in capsys.readouterr().err
