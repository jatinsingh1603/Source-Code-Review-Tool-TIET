"""Helpers for the CodeKavach review workflow (.github/workflows/codekavach-review.yml).

Standard library only: it runs on the Python that the CodeKavach action set up.

    codekavach_summary.py sarif-prefix FILE PREFIX
        Make every artifact URI in a SARIF file relative to the repository root, so code scanning
        can place the alerts on the files (the CLI writes paths relative to the scanned target).

    codekavach_summary.py summary --scan scan.json --findings findings.json --verify verify.json
        Write the Markdown job summary (severity table, top findings, privacy attestation) to
        standard output. The same text is posted as the pull-request comment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ORDER = ["critical", "high", "medium", "low", "info"]
MARKER = "<!-- codekavach-review -->"
TOP = 10


def _load(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def sarif_prefix(path: str, prefix: str) -> int:
    """Prefix relative artifact URIs with ``prefix``; returns the number of URIs changed."""
    prefix = prefix.strip("/")
    if not prefix or prefix == ".":
        return 0
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    changed = 0

    def walk(node: Any) -> None:
        nonlocal changed
        if isinstance(node, dict):
            location = node.get("artifactLocation")
            if isinstance(location, dict):
                uri = location.get("uri")
                if (
                    isinstance(uri, str)
                    and "://" not in uri
                    and not uri.startswith("/")
                    and not uri.startswith(prefix + "/")
                    and "uriBaseId" not in location
                ):
                    location["uri"] = f"{prefix}/{uri}"
                    changed += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(data)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return changed


def _cell(text: object) -> str:
    return str(text).replace("|", "/").replace("\n", " ").strip()


def _blob(prefix: str, path: str, line: int | None) -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("CK_HEAD_SHA") or os.environ.get("GITHUB_SHA", "")
    base = prefix.strip("/")
    full = path if base in ("", ".") or path.startswith(base + "/") else f"{base}/{path}"
    label = f"`{full}:{line}`" if line else f"`{full}`"
    if not repo or not sha:
        return label
    anchor = f"#L{line}" if line else ""
    return f"[{label}]({server}/{repo}/blob/{sha}/{full}{anchor})"


def _findings_section(findings: list[dict[str, Any]], prefix: str) -> list[str]:
    def rank(item: dict[str, Any]) -> tuple[int, str]:
        severity = item.get("severity", "info")
        return (ORDER.index(severity) if severity in ORDER else len(ORDER), item.get("title", ""))

    lines = [f"### Top findings ({min(TOP, len(findings))} of {len(findings)})", ""]
    if not findings:
        return [*lines, "No findings.", ""]
    lines += ["| # | Severity | Finding | CWE | Location |", "|---|---|---|---|---|"]
    for number, item in enumerate(sorted(findings, key=rank)[:TOP], start=1):
        location = (item.get("locations") or [{}])[0]
        cwe = ", ".join(f"CWE-{c}" for c in item.get("cwe") or []) or "-"
        where = _blob(prefix, location.get("path", "?"), location.get("start_line"))
        lines.append(
            f"| {number} | **{item.get('severity', '?')}** | {_cell(item.get('title', ''))} "
            f"| {cwe} | {where} |"
        )
    return [*lines, ""]


def _attestation(scan: dict[str, Any], verify: dict[str, Any]) -> list[str]:
    provider = scan.get("provider") or {}
    egress = scan.get("egress") or {}
    kind = provider.get("kind") or provider.get("id") or "none"
    if kind in ("mock", "replay"):
        where = "answers on the runner and opens no connection; payloads recorded, not transmitted"
    elif kind == "none" or not provider:
        where = "deterministic analysis only; nothing prepared for a model"
    elif provider.get("remote"):
        where = "remote provider; sanitised payloads were sent and recorded in the ledger"
    else:
        where = "local provider"
    lines = ["### Privacy attestation", "", "| Check | Result |", "|---|---|"]
    lines.append(f"| Privacy level | **{scan.get('privacy_level', '?')}** |")
    lines.append(f"| LLM provider | `{provider.get('id', 'none')}` ({where}) |")
    lines.append(
        f"| Model requests | {egress.get('recorded', 0)} recorded in the egress ledger, "
        f"{egress.get('blocked', 0)} blocked by the egress guard |"
    )
    if not verify:
        lines += ["| Ledger verification | not run |", ""]
        return lines
    data = verify.get("data") or {}
    chain = data.get("chain") or {}
    payloads = data.get("payloads") or {}
    terms = data.get("terms") or {}
    chain_text = (
        f"intact, {data.get('records', 0)} records"
        if chain.get("ok")
        else f"BROKEN at seq {chain.get('first_bad_seq')} ({chain.get('reason')})"
    )
    lines.append(f"| Ledger hash chain | {chain_text} |")
    unread = len(payloads.get("missing") or []) + len(payloads.get("unreadable") or [])
    lines.append(
        f"| Stored payloads | {data.get('payloads_checked', 0)} distinct payloads re-hashed, "
        f"{len(payloads.get('mismatched') or [])} mismatches, {unread} missing or unreadable |"
    )
    hits = terms.get("hits") or []
    checked = terms.get("checked", 0)
    if checked:
        verdict = "**PASSED**" if not hits and verify.get("ok") else "**FAILED**"
        lines.append(
            f"| Zero-leak check | {verdict}: {checked} planted secrets and identifiers searched "
            f"verbatim in every stored payload, {len(hits)} occurrence(s) |"
        )
    lines.append(f"| Verification exit code | {verify.get('exit_code', '?')} |")
    lines += [
        "",
        "The zero-leak check is verbatim only: structure (control flow, library calls) is still "
        "disclosed at L3, and `codekavach eval leakage` measures that separately.",
        "",
    ]
    return lines


def summary(args: argparse.Namespace) -> str:
    """The Markdown summary."""
    scan = (_load(args.scan).get("data")) or {}
    findings = (_load(args.findings).get("data") or {}).get("findings") or []
    verify = _load(args.verify)
    counts = dict.fromkeys(ORDER, 0)
    for item in findings:
        counts[item.get("severity", "info")] = counts.get(item.get("severity", "info"), 0) + 1
    highest = next((s for s in ORDER if counts.get(s)), "none")
    gate = args.fail_on
    over = gate != "none" and highest != "none" and ORDER.index(highest) <= ORDER.index(gate)
    gate_text = (
        f"**would fail** (`fail-on: {gate}`; the demo job continues on error, so the run "
        "stays green)"
        if over
        else f"passes (`fail-on: {gate}`)"
    )
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    lines = [
        MARKER,
        f"## CodeKavach security review: `{args.prefix}`",
        "",
        f"**{len(findings)} findings**, highest severity **{highest}**. Gate: {gate_text}.",
        f"Scan `{scan.get('scan_id', '?')}`.",
        "",
        "| Severity | Findings |",
        "|---|---:|",
        *(f"| {severity} | {counts[severity]} |" for severity in ORDER),
        "",
        *_findings_section(findings, args.prefix),
        *_attestation(scan, verify),
    ]
    if repo:
        links = [f"[Workflow run]({server}/{repo}/actions/runs/{run})"] if run else []
        alerts = f"{server}/{repo}/security/code-scanning?query=tool%3ACodeKavach"
        links.append(f"[Code scanning alerts]({alerts})")
        lines += [
            "### Evidence",
            "",
            " | ".join(links),
            "",
            "The run's artifact `codekavach-reports` holds the HTML and PDF reports, the SARIF "
            "file and the ledger verification.",
            "",
        ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    fix = sub.add_parser("sarif-prefix")
    fix.add_argument("file")
    fix.add_argument("prefix")
    summ = sub.add_parser("summary")
    summ.add_argument("--scan", required=True)
    summ.add_argument("--findings", required=True)
    summ.add_argument("--verify", default="")
    summ.add_argument("--fail-on", default="critical")
    summ.add_argument("--prefix", default=".")
    args = parser.parse_args(argv)
    if args.command == "sarif-prefix":
        changed = sarif_prefix(args.file, args.prefix)
        sys.stdout.write(f"{changed} SARIF location(s) made repository-relative\n")
        return 0
    sys.stdout.write(summary(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
