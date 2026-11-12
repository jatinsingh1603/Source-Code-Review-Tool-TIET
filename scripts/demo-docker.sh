#!/usr/bin/env bash
# Bring up the CodeKavach stack from the PUBLISHED image and make the dashboard demo-ready.
#
#   scripts/demo-docker.sh              pull ghcr image, start, wait for health, print URL + login
#   scripts/demo-docker.sh --seed       also run a sample scan (mock provider, no key) via the API
#   scripts/demo-docker.sh --build      build the image locally instead of pulling (offline rehearsal)
#   scripts/demo-docker.sh --down       stop the stack (keeps data); add --purge to delete the volume
#
# Environment (all optional): CODEKAVACH_IMAGE, CODEKAVACH_PORT, CODEKAVACH_ADMIN_PASSWORD.
# The LLM key is never read or printed here; put it in .env (see docs/demo/docker.md).
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${CODEKAVACH_IMAGE:-ghcr.io/jatinsingh1603/codekavach:main}"
PORT="${CODEKAVACH_PORT:-8080}"
BASE="http://127.0.0.1:${PORT}"
ADMIN_USER="${CODEKAVACH_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${CODEKAVACH_ADMIN_PASSWORD:-kavach-admin}"
WAIT_SECONDS="${CODEKAVACH_WAIT_SECONDS:-120}"

seed=0 build=0 down=0 purge=0
for arg in "$@"; do
  case "$arg" in
    --seed) seed=1 ;;
    --build) build=1 ;;
    --down) down=1 ;;
    --purge) purge=1 ;;
    -h | --help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null || { echo "docker is not installed" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "docker compose v2 is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

export CODEKAVACH_IMAGE="$IMAGE" CODEKAVACH_PORT="$PORT" CODEKAVACH_ADMIN_PASSWORD="$ADMIN_PASSWORD"

if [ "$build" = 1 ]; then
  export CODEKAVACH_IMAGE="${CODEKAVACH_IMAGE_LOCAL:-codekavach:local}"
  compose=(docker compose)
else
  compose=(docker compose -f docker-compose.yml -f deploy/docker/compose.ghcr.yml)
fi

if [ "$down" = 1 ]; then
  if [ "$purge" = 1 ]; then "${compose[@]}" down --volumes; else "${compose[@]}" down; fi
  exit 0
fi

if [ "$build" = 1 ]; then
  "${compose[@]}" up -d --build
else
  echo "Pulling ${IMAGE} ..."
  if ! "${compose[@]}" pull codekavach; then
    cat >&2 <<EOF

Could not pull ${IMAGE}. Either the package is private (the owner must set it public in the
GitHub package settings), you are offline, or the image has not been published yet.
Offline rehearsal:  scripts/demo-docker.sh --build
EOF
    exit 1
  fi
  "${compose[@]}" up -d --no-build
fi

echo -n "Waiting for ${BASE}/api/v1/health "
deadline=$((SECONDS + WAIT_SECONDS))
until curl -fsS "${BASE}/api/v1/health" >/dev/null 2>&1; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo
    echo "Timed out after ${WAIT_SECONDS}s. Last container logs:" >&2
    "${compose[@]}" logs --tail 40 codekavach >&2 || true
    exit 1
  fi
  echo -n "."
  sleep 2
done
echo " ok"
curl -fsS "${BASE}/api/v1/health"
echo

if [ "$seed" = 1 ]; then
  scripts/demo-docker-seed.sh "$BASE" "$ADMIN_USER" "$ADMIN_PASSWORD"
fi

cat <<EOF

CodeKavach is running.
  Dashboard : ${BASE}
  API docs  : ${BASE}/docs
  Login     : ${ADMIN_USER} / ${ADMIN_PASSWORD}   (change CODEKAVACH_ADMIN_PASSWORD in .env for anything beyond a demo)
  Image     : ${CODEKAVACH_IMAGE}
  Stop      : scripts/demo-docker.sh --down
EOF
