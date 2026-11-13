#!/usr/bin/env bash
# Entry point of the CodeKavach action. Inputs arrive as CK_* environment variables.
# Secrets (provider keys, GITHUB_TOKEN) are read by the CLI from the environment and never echoed.
set -uo pipefail

target="${CK_TARGET:-.}"
level="${CK_LEVEL:-L3}"
provider="${CK_PROVIDER:-none}"
fail_on="${CK_FAIL_ON:-high}"
out="${RUNNER_TEMP:-/tmp}/codekavach"
mkdir -p "$out"

# Refuse the pull-request-hijack pattern: pull_request_target runs with the base repository's
# secrets while the scanned code is attacker-controlled.
if [ "${GITHUB_EVENT_NAME:-}" = "pull_request_target" ] && [ "$provider" != "none" ]; then
  echo "::error::Refusing to run an LLM provider on a pull_request_target trigger: secrets would be reachable from untrusted code. Analyse on pull_request with provider 'none' and publish from a workflow_run job (see action/examples/codekavach-pr.yml)."
  exit 2
fi

# A hosted runner has no OS keyring, so the default vault key source is unavailable and the
# privacy-prepare stage (and with it every LLM review) would be skipped. Unless the workflow chose
# a key source, use a random passphrase for this job: the vault does not outlive the runner.
if [ -z "${CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE:-}" ]; then
  CK_RUN_VAULT_PASSPHRASE="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  echo "::add-mask::$CK_RUN_VAULT_PASSPHRASE"
  export CK_RUN_VAULT_PASSPHRASE
  export CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE=passphrase
  export CODEKAVACH_PRIVACY__VAULT__PASSPHRASE=env:CK_RUN_VAULT_PASSPHRASE
fi

args=(--json scan "$target" --privacy-level "$level" --fail-on critical)
case "$provider" in
  none) args+=(--no-llm) ;;
  *) args+=(--provider "$provider") ;;
esac
[ -n "${CK_MODEL:-}" ] && args+=(--model "$CK_MODEL")

codekavach "${args[@]}" > "$out/scan.json"
status=$?
# Exit 1 only means the built-in threshold was exceeded; the gate below decides.
if [ ! -s "$out/scan.json" ] || [ $status -gt 1 ]; then
  echo "::error::CodeKavach scan failed (exit $status)."
  head -c 2000 "$out/scan.json" 2>/dev/null
  exit $status
fi

codekavach findings "$target" --format sarif > "$out/codekavach.sarif"
codekavach --json findings "$target" > "$out/findings.json"

python - "$out/findings.json" "$fail_on" <<'PY'
import json, os, re, sys


def cell(value):
    """Untrusted text as one literal table cell: no HTML, links, images, mentions or breaks."""
    value = re.sub(r"[\r\n]+", " ", str(value)).replace("\\", "\\\\").replace("|", "\\|")
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = re.sub(r"([\[\]!*_~])", r"\\\1", value.replace("`", "'"))
    return re.sub(r"@(?=\w)", "@​", value)


def code(value):
    """Untrusted text inside a one-backtick code span in a table cell."""
    return re.sub(r"[\r\n]+", " ", str(value)).replace("`", "'").replace("|", "\\|")


data = json.load(open(sys.argv[1]))["data"]
order = ["info", "low", "medium", "high", "critical"]
sev = [f["severity"] for f in data["findings"] if f["status"] in ("open", "confirmed")]
top = max(sev, key=order.index) if sev else "none"
gate = sys.argv[2]
failed = bool(sev) and gate != "none" and order.index(top) >= order.index(gate)
lines = {
    "scan-id": data["scan_id"],
    "findings-count": str(len(data["findings"])),
    "highest-severity": top,
    "sarif-path": os.path.join(os.path.dirname(sys.argv[1]), "codekavach.sarif"),
    "outcome": "failed" if failed else "passed",
}
with open(os.environ.get("GITHUB_OUTPUT", os.devnull), "a") as handle:
    for key, value in lines.items():
        handle.write(f"{key}={value}\n")
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a") as handle:
        handle.write("## CodeKavach security review\n\n")
        handle.write(f"{len(data['findings'])} finding(s); highest severity: **{top}**.\n\n")
        handle.write("| Severity | Finding | Location |\n|---|---|---|\n")
        for f in sorted(data["findings"], key=lambda f: -order.index(f["severity"]))[:50]:
            loc = f["locations"][0]
            where = code(f"{loc['path']}:{loc['start_line']}")
            handle.write(f"| {cell(f['severity'])} | {cell(f['title'])} | `{where}` |\n")
print(f"{len(data['findings'])} findings, highest {top}, gate {gate}: {lines['outcome']}")
PY

if [ "${CK_SYNC_ISSUES:-false}" = "true" ]; then
  codekavach sync github "$target" --repo "${GITHUB_REPOSITORY:?}" || echo "::warning::issue sync failed"
fi
exit 0
