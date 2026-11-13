#!/usr/bin/env bash
# Seed a running CodeKavach server with one sample scan so the dashboard has data.
# Uses the REST API only (curl, no jq) and the offline "mock" provider: no key, no network.
#
#   scripts/demo-docker-seed.sh http://127.0.0.1:8080 admin kavach-admin
set -euo pipefail

BASE="${1:-http://127.0.0.1:8080}"
USER_NAME="${2:-admin}"
PASSWORD="${3:-kavach-admin}"
API="${BASE}/api/v1"
TIMEOUT="${CODEKAVACH_SEED_TIMEOUT:-300}"

# Pull a top-level-ish string field out of a JSON document without jq.
field() { sed -n 's/.*"'"$1"'" *: *"\([^"]*\)".*/\1/p' | head -n 1; }

login=$(curl -fsS -X POST "${API}/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${USER_NAME}\",\"password\":\"${PASSWORD}\"}") || {
  echo "login failed: check the admin password" >&2
  exit 1
}
token=$(printf '%s' "$login" | field token)
[ -n "$token" ] || { echo "no token in login response" >&2; exit 1; }
auth=(-H "Authorization: Bearer ${token}")

# The server creates "KavachBank (sample)" on first start; scan that project instead of adding a
# second copy of it. Create it only if it has been deleted.
project_id=prj_kavachbank_sample
if ! curl -fsS "${API}/projects/${project_id}" "${auth[@]}" >/dev/null 2>&1; then
  project=$(curl -fsS -X POST "${API}/projects" "${auth[@]}" -H 'Content-Type: application/json' \
    -d '{"name":"KavachBank (sample)","description":"Bundled sample project","source":{"type":"sample"}}')
  project_id=$(printf '%s' "$project" | field id)
  [ -n "$project_id" ] || { echo "could not create the sample project: $project" >&2; exit 1; }
fi

scan=$(curl -fsS -X POST "${API}/projects/${project_id}/scans" "${auth[@]}" \
  -H 'Content-Type: application/json' -d '{"provider":"mock"}')
scan_id=$(printf '%s' "$scan" | field id)
[ -n "$scan_id" ] || { echo "could not start the scan: $scan" >&2; exit 1; }

echo -n "Scanning ${scan_id} (mock provider) "
deadline=$((SECONDS + TIMEOUT))
while :; do
  status=$(curl -fsS "${API}/scans/${scan_id}" "${auth[@]}" | field status)
  case "$status" in
    completed | complete | succeeded | done | failed | cancelled | error) break ;;
  esac
  [ "$SECONDS" -lt "$deadline" ] || { echo; echo "timed out; status=${status}" >&2; exit 1; }
  echo -n "."
  sleep 3
done
echo " ${status}"
[ "$status" = failed ] || [ "$status" = error ] && exit 1
exit 0
