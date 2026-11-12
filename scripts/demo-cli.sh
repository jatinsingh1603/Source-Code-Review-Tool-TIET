#!/usr/bin/env bash
# CodeKavach terminal walkthrough: a paced, annotated tour of the CLI on the sample bank project.
#
#   scripts/demo-cli.sh            press Enter between steps
#   scripts/demo-cli.sh --auto     no pauses (rehearsal, CI, transcript)
#   scripts/demo-cli.sh --provider mock|agentrouter   force a provider
#   scripts/demo-cli.sh --out DIR  keep everything in DIR (default: a new temp dir)
#
# Provider: agentrouter when CODEKAVACH_AGENTROUTER_API_KEY is set (and the provider exists in this
# build), otherwise the offline mock. The key is only ever read from the environment; this script
# never prints it and never writes it to a file.
#
# The walkthrough scans a throw-away copy of fixtures/kavachbank (without its answer key), in a
# state directory of its own, so it never touches your project or your ledger. A step whose command
# is not in this build is shown as "skipped" with the reason, not as a failure.
set -u

AUTO=0 PROVIDER="" OUT="" PACE="${DEMO_PACE:-0}"
while [ $# -gt 0 ]; do
  case "$1" in
    --auto) AUTO=1 ;;
    --provider) PROVIDER="${2:?--provider needs a value}"; shift ;;
    --out) OUT="${2:?--out needs a directory}"; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$ROOT/fixtures/kavachbank"
[ -d "$FIXTURE" ] || { echo "fixture not found at $FIXTURE" >&2; exit 2; }

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$'\033[1m' D=$'\033[2m' C=$'\033[36m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' M=$'\033[35m' Z=$'\033[0m'
else
  B="" D="" C="" G="" Y="" R="" M="" Z=""
fi

# --- which codekavach -------------------------------------------------------------------------
if [ -n "${CODEKAVACH_BIN:-}" ]; then CK=("$CODEKAVACH_BIN")
elif command -v uv >/dev/null 2>&1 && [ -f "$ROOT/pyproject.toml" ]; then CK=(uv run --project "$ROOT" codekavach)
elif command -v codekavach >/dev/null 2>&1; then CK=(codekavach)
else echo "codekavach is not installed; run: uv sync --all-extras" >&2; exit 2; fi

# --- throw-away workspace ---------------------------------------------------------------------
if [ -z "$OUT" ]; then OUT="$(mktemp -d "${TMPDIR:-/tmp}/codekavach-demo-XXXXXX")"; fi
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
PROJ="$OUT/kavachbank"
rm -rf "$PROJ" "$OUT/home" "$OUT/reports"
cp -r "$FIXTURE" "$PROJ"
rm -rf "$PROJ/ground-truth"
mkdir "$PROJ/.git"   # marks the copy as a project root; it is not a repository
TERMS="$FIXTURE/ground-truth/terms.txt"

export CODEKAVACH_HOME="$OUT/home"
DEMO_PASS="demo-$RANDOM-$RANDOM-$RANDOM-$RANDOM"
export CODEKAVACH_DEMO_PASSPHRASE="$DEMO_PASS"
export CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE=passphrase
export CODEKAVACH_PRIVACY__VAULT__PASSPHRASE=env:CODEKAVACH_DEMO_PASSPHRASE

# --- provider choice --------------------------------------------------------------------------
if [ -z "$PROVIDER" ]; then
  PROVIDER=mock
  if [ -n "${CODEKAVACH_AGENTROUTER_API_KEY:-}" ] \
     && (cd "$PROJ" && "${CK[@]}" providers list 2>&1 | grep -qi agentrouter); then
    PROVIDER=agentrouter
  fi
fi
EGRESS=()
if [ "$PROVIDER" != mock ] && [ "$PROVIDER" != replay ]; then EGRESS=(--accept-egress); fi

# --- step machinery ---------------------------------------------------------------------------
N=0 OK=0 SKIP=0 FAIL=0 OKCODES="0"
pause() {
  if [ "$AUTO" = 1 ]; then if [ "$PACE" != 0 ]; then sleep "$PACE"; fi; return 0; fi
  printf '%s' "${D}  [press Enter to run]${Z}"
  read -r _ </dev/tty 2>/dev/null || read -r _ || true
  printf '\r\033[K'
}
header() {
  N=$((N + 1)); printf '\n%s== Step %d: %s ==%s\n' "$B$C" "$N" "$1" "$Z"
  printf '%s%s%s\n' "$D" "$2" "$Z"
}
proves() { printf '%s  proves:%s %s\n' "$G$B" "$Z" "$1"; }

# step "title" "what to say" "what it proves" -- codekavach-args...
# Runs in the project copy. Exit codes listed in $OKCODES count as success (reset after each step).
step() {
  local title="$1" say="$2" claim="$3"; shift 4
  header "$title" "$say"; pause
  printf '%s$ codekavach %s%s\n' "$M" "$*" "$Z"
  local log="$OUT/step-$N.log" rc
  if [ "${CLEAN:-0}" = 1 ]; then
    # the vault settings above exist only for the scan; checking the bare machine must not see them
    (cd "$PROJ" && env -u CODEKAVACH_DEMO_PASSPHRASE -u CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE -u CODEKAVACH_PRIVACY__VAULT__PASSPHRASE "${CK[@]}" "$@") >"$log" 2>&1; rc=$?
  else
    (cd "$PROJ" && "${CK[@]}" "$@") >"$log" 2>&1; rc=$?
  fi
  cat "$log"
  if [[ " $OKCODES " == *" $rc "* ]]; then OK=$((OK + 1)); proves "$claim"
  elif grep -qiE "No such command|No such option|not in this build|no adapter for provider|delivered by epic|is not available|unknown provider" "$log"; then
    SKIP=$((SKIP + 1)); printf '%s  skipped:%s not in this build yet (exit %d)\n' "$Y$B" "$Z" "$rc"
  else FAIL=$((FAIL + 1)); printf '%s  FAILED:%s exit code %d (log: %s)\n' "$R$B" "$Z" "$rc" "$log"; fi
  OKCODES="0"; CLEAN=0
}

printf '%s' "$B$C"
cat <<'BANNER'
   ____          _      _  __                _
  / ___|___   __| | ___| |/ /__ ___   ____ _| |__
 | |   / _ \ / _` |/ _ \ ' // _` \ \ / / _` | '_ \
 | |__| (_) | (_| |  __/ . \ (_| |\ V / (_| | | | |
  \____\___/ \__,_|\___|_|\_\__,_| \_/ \__,_|_| |_|
BANNER
printf '%s\n' "$Z  privacy-preserving, LLM-assisted secure code review   (terminal walkthrough)"
printf '%s  provider: %s%s\n' "$D" "$PROVIDER" "$Z"
if [ "$PROVIDER" = mock ]; then printf '%s  the mock answers on this machine: no key, no network.%s\n' "$D" "$Z"; fi

step "Version" "Start with what is installed." \
  "the CLI is installed and versioned" -- --version

CLEAN=1
step "Doctor: is this machine ready?" "One command checks runtime, parsers, storage, engines and providers." \
  "every prerequisite is verified up front; optional parts are warnings with an install hint, never silent gaps" -- doctor

step "Providers: who could review the code" "Each provider has a locality and a minimum privacy level." \
  "providers are an explicit, inspectable list; local ones never leave the machine" -- providers list

step "Providers: does the chosen one answer?" "A constant probe; no code is involved." \
  "the $PROVIDER provider answers before any code is prepared" -- \
  providers test "$PROVIDER" "${EGRESS[@]}"

OKCODES="0 1"
step "Scan the sample bank" "A synthetic bank with planted vulnerabilities and secrets. Exit 1 only means findings at or above the threshold." \
  "engines and the model find the planted issues; the summary names the provider and what was recorded" -- \
  scan . --provider "$PROVIDER" "${EGRESS[@]}"

step "Privacy: what would the model see?" "The exact payloads prepared for the provider." \
  "a payload is a slice with pseudonyms, not the file" -- privacy inspect . --list

step "Privacy: side by side" "Original code left, exact payload right." \
  "secrets are typed placeholders and identifiers are renamed, on one page that loads nothing from the network" -- \
  privacy inspect . --html "$OUT/inspect.html"

step "Privacy: audit the ledger" "Hash chain, payload hashes, and a search for every planted term in every payload." \
  "no listed secret or domain term occurs verbatim in anything prepared for a model, and the log cannot be edited unnoticed" -- \
  privacy ledger verify . --check-terms "$TERMS" --include-blocked

step "Privacy: explain a decision" "Why was a value redacted or renamed?" \
  "the privacy level of any file is explained axis by axis (path, language, rule, classification)" -- privacy explain services/api/interest_engine.py

# Ask the build which formats exist, so a format that has not landed is skipped, not a failure.
WANT="html pdf sarif xlsx docx"; FORMATS=""
AVAIL="$(cd "$PROJ" && "${CK[@]}" report . --format __probe__ 2>&1 | tr '\n' ' ' | sed -n 's/.*available formats: *//p' | tr -d ',')"
if [ -n "$AVAIL" ]; then for f in $WANT; do case " $AVAIL " in *" $f "*) FORMATS="${FORMATS:+$FORMATS,}$f" ;; esac; done
else FORMATS="${WANT// /,}"; fi
step "Reports in every format" "One scan, rendered for different readers." \
  "one scan yields $FORMATS (SARIF is for code scanning, XLSX for triage, DOCX for the client)" -- \
  report . --format "$FORMATS" --output-dir "$OUT/reports"
if [ -d "$OUT/reports" ]; then printf '%s' "$D"; ls -1 "$OUT/reports" | sed 's/^/    /'; printf '%s' "$Z"; fi

step "Send findings to GitHub (dry run)" "Issues and a project board; here only what would change." \
  "findings reach the client's tracker without code leaving, and dry-run changes nothing" -- \
  sync github . --repo example-org/kavachbank --dry-run

step "Leakage: what could a curious provider learn?" "Beyond verbatim terms: attack the payloads and measure." \
  "privacy is measured, not asserted" -- eval leakage --level L3

printf '\n%s== Done: %d ok, %d skipped (not in this build), %d failed ==%s\n' "$B$C" "$OK" "$SKIP" "$FAIL" "$Z"
printf '%s  files: %s%s\n' "$D" "$OUT" "$Z"
[ "$FAIL" = 0 ]
