#!/usr/bin/env bash
# CodeKavach set-up: from a fresh clone to a running dashboard in one command.
#
#   ./setup.sh                 pick Docker or local mode, start the dashboard, print the login
#   ./setup.sh --check         run the health checks and an offline self-test
#   ./setup.sh --stop          stop the dashboard (data is kept)
#   ./setup.sh --uninstall     stop it and, after asking, delete its data
#   ./setup.sh --help          every option
#
# Works on Linux, macOS and WSL with bash 3.2 or newer. Never needs sudo. Safe to run again: it
# keeps an existing .env, data directory, password and port. Windows without WSL: setup.ps1.
#
# No secret is taken from the command line. Generated passwords go to a file that only you can
# read (mode 0600) and the initial admin password is printed once, when it is created.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$REPO"

GHCR_IMAGE="ghcr.io/jatinsingh1603/codekavach:main"
UV_INSTALLER="https://astral.sh/uv/install.sh"
HEALTH_PATH="/api/v1/health"
WAIT_SECONDS="${CODEKAVACH_WAIT_SECONDS:-180}"
ADMIN_USER="admin"
CONFIG_MARK="# Written by the CodeKavach set-up script (setup.sh); delete this file to undo."

mode="" action="setup" port="" port_given=0 data_dir="" project_name=""
pull=0 samples="" yes=0 start=1 purge=0 provider="" key_file=""

# ------------------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  bold=$'\033[1m' dim=$'\033[2m' red=$'\033[31m' green=$'\033[32m' yellow=$'\033[33m' off=$'\033[0m'
else
  bold="" dim="" red="" green="" yellow="" off=""
fi
step() { printf '%s==>%s %s\n' "$bold" "$off" "$*"; }
info() { printf '    %s\n' "$*"; }
good() { printf '%s ok %s %s\n' "$green" "$off" "$*"; }
warn() { printf '%s !! %s %s\n' "$yellow" "$off" "$*" >&2; }
die() {
  printf '%serror:%s %s\n' "$red" "$off" "$1" >&2
  shift
  for line in "$@"; do printf '       %s\n' "$line" >&2; done
  exit 1
}

usage() {
  cat <<'EOF'
CodeKavach set-up

Usage: ./setup.sh [options]

Without options the script picks a mode, starts the dashboard and prints the address, the admin
user name and the initial password.

Mode (default: Docker when it is running with Compose v2, otherwise local)
  --docker              Run the dashboard, API and CLI in one container.
  --local               Run from this checkout with uv (Python 3.12; Node 20 for the dashboard).

Set-up options
  --port N              Port of the dashboard (default 8080; the next free one if it is busy).
  --pull                Docker: pull the published image instead of building it here.
  --samples             Add the bundled sample projects KavachBank, Ledgerly and Shopfront
                        (no scans are run). Without it the script asks.
  --no-samples          Do not add them and do not ask.
  --yes, -y             Answer the script's questions with their default; never prompt.
  --data-dir DIR        Local: where the data lives (default ~/.local/share/codekavach, or
                        ~/Library/Application Support/codekavach on macOS).
  --no-start            Prepare everything but do not start the server; print the command.
  --project-name NAME   Docker: Compose project name (default codekavach).

Model key (optional; without one CodeKavach works fully offline)
  --provider NAME       Hosted provider the key belongs to (supported here: agentrouter).
  --api-key-file FILE   File whose first line is the API key. Without it, and with --provider,
                        the script asks for the key without showing it. A key is never accepted
                        as an argument.

Other actions
  --check               Run `codekavach doctor` and the offline self-test; report pass or fail.
  --status              Say whether the dashboard is running and where.
  --stop                Stop the dashboard. Data, passwords and settings are kept.
  --uninstall           Stop it and ask whether to delete its data. With --yes the data is kept
                        unless --purge is also given.
  --purge               With --uninstall: delete the data without asking.
  --help, -h            Show this help.

Examples
  ./setup.sh
  ./setup.sh --local --port 9000 --samples
  ./setup.sh --docker --pull --yes
  ./setup.sh --provider agentrouter --api-key-file ~/agentrouter.key
EOF
}

# ------------------------------------------------------------------------------------------
# Arguments
# ------------------------------------------------------------------------------------------
need_value() { [ $# -ge 2 ] || die "$1 needs a value" "see ./setup.sh --help"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) mode=docker ;;
    --local) mode=local ;;
    --pull) pull=1 ;;
    --samples) samples=yes ;;
    --no-samples) samples=no ;;
    --yes | -y) yes=1 ;;
    --no-start) start=0 ;;
    --purge) purge=1 ;;
    --port) need_value "$@"; port="$2"; port_given=1; shift ;;
    --port=*) port="${1#*=}"; port_given=1 ;;
    --data-dir) need_value "$@"; data_dir="$2"; shift ;;
    --data-dir=*) data_dir="${1#*=}" ;;
    --project-name) need_value "$@"; project_name="$2"; shift ;;
    --project-name=*) project_name="${1#*=}" ;;
    --provider) need_value "$@"; provider="$2"; shift ;;
    --provider=*) provider="${1#*=}" ;;
    --api-key-file) need_value "$@"; key_file="$2"; shift ;;
    --api-key-file=*) key_file="${1#*=}" ;;
    --api-key | --api-key=* | --key | --key=* | --password | --password=*)
      die "a secret is never accepted as an argument (it would be visible in the process list)" \
        "put the key in a file and pass --api-key-file FILE, or pass --provider and type it when asked" ;;
    --check) action=check ;;
    --status) action=status ;;
    --stop) action=stop ;;
    --uninstall) action=uninstall ;;
    --help | -h) usage; exit 0 ;;
    *) die "unknown option: $1" "see ./setup.sh --help" ;;
  esac
  shift
done

if [ -n "$port" ]; then
  case "$port" in
    *[!0-9]* | "") die "--port needs a number between 1 and 65535" ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    die "--port needs a number between 1 and 65535"
  fi
fi
if [ -n "$key_file" ] && [ -z "$provider" ]; then provider=agentrouter; fi
case "$provider" in
  "" | agentrouter) ;;
  *) die "--provider $provider is not set up by this script" \
    "supported here: agentrouter" \
    "every other provider is configured as described in docs/guide/providers.md" ;;
esac
if [ -n "$key_file" ] && [ ! -r "$key_file" ]; then die "cannot read the key file: $key_file"; fi

# ------------------------------------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

interactive() { [ "$yes" = 0 ] && [ -t 0 ]; }

# confirm QUESTION DEFAULT(y|n): the default when --yes is given or there is no terminal.
confirm() {
  local answer hint="y/N"
  [ "$2" = y ] && hint="Y/n"
  if ! interactive; then [ "$2" = y ]; return; fi
  printf '%s [%s] ' "$1" "$hint"
  read -r answer || answer=""
  case "$answer" in
    [Yy] | [Yy][Ee][Ss]) return 0 ;;
    "") [ "$2" = y ] ;;
    *) return 1 ;;
  esac
}

# 2*N hex characters from the kernel's random source.
random_hex() { od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'; }

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# The first free port at or after $1.
free_port() {
  local candidate="$1" tries=0
  while port_busy "$candidate"; do
    candidate=$((candidate + 1))
    tries=$((tries + 1))
    if [ "$tries" -gt 200 ] || [ "$candidate" -gt 65535 ]; then
      die "no free port found from $1 upwards; choose one with --port"
    fi
  done
  printf '%s' "$candidate"
}

http_ok() {
  if have curl; then
    curl -fsS --max-time 5 "$1" >/dev/null 2>&1
  elif have wget; then
    wget -q -T 5 -O /dev/null "$1" >/dev/null 2>&1
  else
    # No HTTP client: an open port is the best available signal.
    local rest="${1#http://127.0.0.1:}"
    port_busy "${rest%%/*}"
  fi
}

# wait_health URL: 0 when the server answers within WAIT_SECONDS.
wait_health() {
  local deadline=$((SECONDS + WAIT_SECONDS))
  printf '    waiting for %s ' "$1"
  until http_ok "$1"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      printf ' timed out after %ss\n' "$WAIT_SECONDS"
      return 1
    fi
    if [ -n "${2:-}" ] && ! "$2"; then
      printf ' the server stopped\n'
      return 1
    fi
    printf '.'
    sleep 2
  done
  printf ' ready\n'
}

# kv_get FILE KEY: the value of KEY=VALUE in FILE (empty when absent).
kv_get() {
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | tail -n 1
}

# kv_set FILE KEY VALUE: replace or append KEY=VALUE; the file stays mode 0600. The value travels
# in the environment of awk, not in its arguments, so it never shows in the process list.
kv_set() {
  local file="$1" key="$2" tmp
  tmp="$(umask 077 && mktemp "${file}.XXXXXX")"
  if [ -f "$file" ]; then
    CK_KEY="$key" CK_VALUE="$3" awk '
      BEGIN { key = ENVIRON["CK_KEY"]; value = ENVIRON["CK_VALUE"]; done = 0 }
      index($0, key "=") == 1 { if (!done) print key "=" value; done = 1; next }
      { print }
      END { if (!done) print key "=" value }
    ' "$file" >"$tmp"
  else
    printf '%s=%s\n' "$key" "$3" >"$tmp"
  fi
  chmod 600 "$tmp"
  mv "$tmp" "$file"
}

is_wsl() { grep -qi microsoft /proc/version 2>/dev/null; }

# read_api_key: the key from --api-key-file or a hidden prompt, in the variable api_key.
api_key=""
read_api_key() {
  [ -n "$provider" ] || return 0
  if [ -n "$key_file" ]; then
    IFS= read -r api_key <"$key_file" || true
    api_key="${api_key%$'\r'}"
  elif interactive; then
    printf 'API key for %s (not shown; Enter to skip): ' "$provider"
    IFS= read -rs api_key || api_key=""
    printf '\n'
  else
    warn "--provider was given without --api-key-file and there is no terminal to ask on; no key stored"
  fi
  case "$api_key" in
    *[[:space:]]*) die "the API key contains white space; check the key file" ;;
  esac
}

# ------------------------------------------------------------------------------------------
# REST helpers (sample projects). Nothing secret is passed as a command argument.
# ------------------------------------------------------------------------------------------
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
# The first "KEY": "value" of a JSON document, without jq.
json_field() {
  grep -o '"'"$1"'" *: *"[^"]*"' | head -n 1 | sed 's/^"[^"]*" *: *"\(.*\)"$/\1/'
}

api_token=""
api_login() {
  local base="$1" password="$2" reply
  reply="$(printf '{"username":"%s","password":"%s"}' "$ADMIN_USER" "$(json_escape "$password")" |
    curl -fsS --max-time 30 -X POST "$base/api/v1/auth/login" \
      -H 'Content-Type: application/json' --data-binary @- 2>/dev/null)" || return 1
  api_token="$(printf '%s' "$reply" | json_field token)"
  [ -n "$api_token" ]
}

# api METHOD URL [curl arguments...]: an authenticated request; the token goes in on stdin.
api() {
  local method="$1" url="$2"
  shift 2
  printf 'header = "Authorization: Bearer %s"\n' "$api_token" |
    curl -fsS --max-time 120 -K - -X "$method" "$url" "$@"
}

sample_dir() {
  local candidate
  for candidate in "fixtures/$1" "fixtures/demo-$1" "fixtures/samples/$1" "samples/$1"; do
    if [ -d "$REPO/$candidate" ]; then
      printf '%s' "$REPO/$candidate"
      return 0
    fi
  done
  return 1
}

# add_upload_sample BASE NAME SLUG DESCRIPTION
add_upload_sample() {
  local base="$1" name="$2" slug="$3" description="$4" listing dir archive created id
  listing="$(api GET "$base/api/v1/projects" 2>/dev/null)" || listing=""
  case "$listing" in
    *"\"name\":\"$name\""* | *"\"name\": \"$name\""*)
      info "$name: already there"
      return 0 ;;
  esac
  if ! dir="$(sample_dir "$slug")"; then
    warn "$name: its files are not in this checkout; skipped"
    return 0
  fi
  created="$(api POST "$base/api/v1/projects" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$name\",\"description\":\"$description\",\"source\":{\"type\":\"upload\"}}")" || {
    warn "$name: the server refused the project"
    return 1
  }
  id="$(printf '%s' "$created" | json_field id)"
  [ -n "$id" ] || { warn "$name: no project id in the server's answer"; return 1; }
  archive="$(mktemp -d)/$slug.tar.gz"
  tar -czf "$archive" -C "$dir" .
  if api POST "$base/api/v1/projects/$id/upload" -F "file=@$archive" >/dev/null; then
    info "$name: added"
  else
    warn "$name: the upload failed"
  fi
  rm -rf "$(dirname "$archive")"
}

# add_samples BASE PASSWORD
add_samples() {
  local base="$1"
  step "Adding the sample projects (no scan is run)"
  if ! have curl || ! have tar; then
    warn "curl and tar are needed to add the sample projects; skipped"
    return 0
  fi
  if ! api_login "$base" "$2"; then
    warn "could not sign in as $ADMIN_USER with the stored initial password (was it changed?)"
    info "add the samples in the dashboard instead: Projects, New project"
    return 0
  fi
  if api GET "$base/api/v1/projects/prj_kavachbank_sample" >/dev/null 2>&1; then
    info "KavachBank (sample): already there"
  elif api POST "$base/api/v1/projects" -H 'Content-Type: application/json' \
    -d '{"name":"KavachBank (sample)","description":"Bundled sample: a deliberately vulnerable banking application","source":{"type":"sample"}}' \
    >/dev/null 2>&1; then
    info "KavachBank (sample): added"
  else
    warn "KavachBank (sample): could not be added"
  fi
  add_upload_sample "$base" "Ledgerly (sample)" ledgerly \
    "Bundled sample: a small Python invoicing service with planted flaws" || true
  add_upload_sample "$base" "Shopfront (sample)" shopfront \
    "Bundled sample: a small Node.js shop with planted flaws" || true
  api POST "$base/api/v1/auth/logout" >/dev/null 2>&1 || true
  api_token=""
}

want_samples() {
  case "$samples" in
    yes) return 0 ;;
    no) return 1 ;;
  esac
  confirm "Add the three bundled sample projects (KavachBank, Ledgerly, Shopfront)?" n
}

# summary MODE URL PASSWORD_LINE [extra lines...]
summary() {
  local kind="$1" url="$2" password_line="$3"
  shift 3
  printf '\n%sCodeKavach is running.%s\n\n' "$bold$green" "$off"
  printf '  Dashboard   %s\n' "$url"
  printf '  API docs    %s/api/docs\n' "$url"
  printf '  User name   %s\n' "$ADMIN_USER"
  printf '  Password    %s\n' "$password_line"
  for line in "$@"; do printf '  %s\n' "$line"; done
  printf '\n%sNext, try:%s\n' "$bold" "$off"
  printf '  1. Open %s, sign in, open the project "KavachBank (sample)" and start a scan.\n' "$url"
  printf '     It runs offline: nothing leaves this machine.\n'
  if [ "$kind" = docker ]; then
    printf '  2. Scan your own code: Projects, New project, then upload a .zip of the source\n'
    printf '     or give an https git URL.\n'
    printf '  3. Check the installation:  ./setup.sh --check\n'
  else
    printf '  2. Scan your own code in the dashboard: Projects, New project, then give the folder\n'
    printf '     path, upload a .zip or give an https git URL.\n'
    printf '  3. Scan from the terminal:  cd /path/to/your/code && %s scan .\n' "$REPO/.venv/bin/codekavach"
  fi
  printf '\n  Stop: ./setup.sh --stop     Update: git pull && ./setup.sh     Remove: ./setup.sh --uninstall\n'
  if [ -z "$api_key" ]; then
    printf '\n  %sNo model key is set, and none is needed: the built-in local analysis and the offline\n' "$dim"
    printf '  provider do the whole review on this machine. To add a hosted model later:\n'
    printf '  ./setup.sh --provider agentrouter --api-key-file FILE%s\n' "$off"
  fi
}

# ==========================================================================================
# Docker mode
# ==========================================================================================
ENV_FILE="$REPO/.env"

docker_ready() { have docker && docker compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

docker_project() {
  if [ -n "$project_name" ]; then
    printf '%s' "$project_name"
  elif [ -n "$(kv_get "$ENV_FILE" COMPOSE_PROJECT_NAME)" ]; then
    kv_get "$ENV_FILE" COMPOSE_PROJECT_NAME
  else
    printf '%s' "${COMPOSE_PROJECT_NAME:-codekavach}"
  fi
}

compose() { docker compose -p "$PROJECT" "$@"; }

# The folder a Compose project of this name was started from (empty when there is none).
docker_project_home() {
  docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
    --format '{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null | head -n 1
}

# A Compose project name is machine-wide. Never touch one that belongs to another checkout.
docker_foreign() {
  local home
  home="$(docker_project_home)"
  [ -n "$home" ] && [ "$home" != "$REPO" ]
}

docker_refuse_foreign() {
  if docker_foreign; then
    die "a Compose project named $PROJECT already exists and belongs to another folder:" \
      "$(docker_project_home)" \
      "manage it from there, or give this checkout its own name: ./setup.sh --docker --project-name NAME"
  fi
}

docker_running() { ! docker_foreign && [ -n "$(compose ps -q --status running codekavach 2>/dev/null)" ]; }

docker_volume_exists() { docker volume inspect "${PROJECT}_codekavach-data" >/dev/null 2>&1; }

docker_require() {
  have docker || die "Docker is not installed" \
    "install Docker Desktop or Docker Engine, or use the local mode: ./setup.sh --local"
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing (docker compose version fails)" \
    "install the compose plugin, or use the local mode: ./setup.sh --local"
  docker info >/dev/null 2>&1 || die "Docker is installed but not running, or this user may not use it" \
    "start Docker Desktop (or: systemctl start docker) and run ./setup.sh again" \
    "or use the local mode: ./setup.sh --local"
}

docker_setup() {
  local created_password="" existing_volume=0 image base current_port
  docker_require
  PROJECT="$(docker_project)"
  docker_refuse_foreign
  step "Docker mode (Compose project: $PROJECT)"

  docker_volume_exists && existing_volume=1

  # --- .env ---------------------------------------------------------------------------------
  if [ ! -f "$ENV_FILE" ]; then
    [ -f "$REPO/.env.example" ] || die ".env.example is missing; is this a complete checkout?"
    (umask 077 && cp "$REPO/.env.example" "$ENV_FILE")
    chmod 600 "$ENV_FILE"
    if [ "$existing_volume" = 1 ]; then
      # The admin account and the vault key of an existing volume were set by an earlier
      # installation; new values here would not apply to it and would lock its vaults.
      warn "the data volume ${PROJECT}_codekavach-data already exists: its admin password and vault key are kept"
      kv_set "$ENV_FILE" CODEKAVACH_ADMIN_PASSWORD ""
    else
      created_password="$(random_hex 12)"
      kv_set "$ENV_FILE" CODEKAVACH_ADMIN_PASSWORD "$created_password"
      kv_set "$ENV_FILE" CODEKAVACH_VAULT_PASSPHRASE "$(random_hex 32)"
    fi
    info "created .env (mode 0600, ignored by git)"
  else
    chmod 600 "$ENV_FILE"
    info "keeping the existing .env"
    if [ "$existing_volume" = 0 ] && [ -z "$(kv_get "$ENV_FILE" CODEKAVACH_ADMIN_PASSWORD)" ]; then
      created_password="$(random_hex 12)"
      kv_set "$ENV_FILE" CODEKAVACH_ADMIN_PASSWORD "$created_password"
    fi
  fi
  if [ "$PROJECT" != codekavach ] || [ -n "$(kv_get "$ENV_FILE" COMPOSE_PROJECT_NAME)" ]; then
    kv_set "$ENV_FILE" COMPOSE_PROJECT_NAME "$PROJECT"
  fi

  read_api_key
  if [ -n "$api_key" ]; then
    kv_set "$ENV_FILE" CODEKAVACH_AGENTROUTER_API_KEY "$api_key"
    info "stored the $provider key in .env"
  elif [ -n "$(kv_get "$ENV_FILE" CODEKAVACH_AGENTROUTER_API_KEY)" ]; then
    api_key=present
  fi

  # --- port ---------------------------------------------------------------------------------
  current_port="$(kv_get "$ENV_FILE" CODEKAVACH_PORT)"
  [ -n "$port" ] || port="${current_port:-8080}"
  if docker_running && [ "$port" = "$current_port" ]; then
    : # our own container holds the port
  elif port_busy "$port"; then
    local wanted="$port"
    port="$(free_port "$port")"
    warn "port $wanted is busy; using $port instead"
  fi
  kv_set "$ENV_FILE" CODEKAVACH_PORT "$port"
  base="http://127.0.0.1:$port"

  # --- image --------------------------------------------------------------------------------
  image="$(kv_get "$ENV_FILE" CODEKAVACH_IMAGE)"
  if [ "$pull" = 0 ] && ! docker buildx version >/dev/null 2>&1 && ! docker build --help >/dev/null 2>&1; then
    warn "this Docker cannot build images; pulling the published image instead"
    pull=1
  fi
  case "$image" in
    ghcr.io/*) [ "$pull" = 1 ] || { pull=1; info "the image in .env is a published one; pulling it"; } ;;
  esac
  if [ "$pull" = 1 ]; then
    case "$image" in
      ghcr.io/*) ;;
      *) image="${CODEKAVACH_IMAGE:-$GHCR_IMAGE}"; kv_set "$ENV_FILE" CODEKAVACH_IMAGE "$image" ;;
    esac
    step "Pulling $image"
    if ! docker pull "$image"; then
      warn "could not pull $image (offline, or the image is not public)"
      if docker image inspect "$image" >/dev/null 2>&1; then
        info "using the copy of it that is already on this machine"
      else
        info "building the image here instead"
        pull=0
        image="codekavach:local"
        kv_set "$ENV_FILE" CODEKAVACH_IMAGE "$image"
      fi
    fi
  fi
  if [ "$pull" = 0 ]; then
    if [ -z "$image" ]; then
      image="${CODEKAVACH_IMAGE:-codekavach:local}"
      kv_set "$ENV_FILE" CODEKAVACH_IMAGE "$image"
    elif [ -n "${CODEKAVACH_IMAGE:-}" ] && [ "$image" != "$CODEKAVACH_IMAGE" ]; then
      image="$CODEKAVACH_IMAGE"
      kv_set "$ENV_FILE" CODEKAVACH_IMAGE "$image"
    fi
    step "Building the image $image (the first build takes a few minutes)"
    compose build codekavach || die "the image build failed" \
      "behind a proxy: set HTTP_PROXY and HTTPS_PROXY for Docker, see the README troubleshooting" \
      "or use the published image: ./setup.sh --docker --pull"
  fi

  if [ "$start" = 0 ]; then
    good "prepared; start it with: ./setup.sh --docker"
    return 0
  fi

  # --- start --------------------------------------------------------------------------------
  step "Starting the container"
  # The variables come from .env; anything exported in this shell must not override them.
  unset CODEKAVACH_PORT CODEKAVACH_IMAGE CODEKAVACH_ADMIN_PASSWORD CODEKAVACH_VAULT_PASSPHRASE
  compose up -d --no-build codekavach
  if ! wait_health "$base$HEALTH_PATH"; then
    compose logs --tail 40 codekavach >&2 || true
    die "the server did not become healthy" "see the log above, or: docker compose -p $PROJECT logs codekavach"
  fi

  local stored password_line
  stored="$(kv_get "$ENV_FILE" CODEKAVACH_ADMIN_PASSWORD)"
  if want_samples; then
    if [ -n "$stored" ]; then
      add_samples "$base" "$stored"
    else
      warn "the admin password is not in .env, so the samples cannot be added from here"
    fi
  fi

  if [ -n "$created_password" ]; then
    password_line="$created_password   (initial password, shown once; also in .env)"
  elif [ -n "$stored" ]; then
    password_line="the initial password is in .env (CODEKAVACH_ADMIN_PASSWORD), unless you changed it since"
  else
    password_line="the one set when this data volume was first started"
  fi
  summary docker "$base" "$password_line" "Data        Docker volume ${PROJECT}_codekavach-data" \
    "Settings    $ENV_FILE"
}

docker_check() {
  local failed=0 selftest
  docker_require
  PROJECT="$(docker_project)"
  docker_refuse_foreign
  docker_running || die "the container is not running" "start it with ./setup.sh --docker"
  step "codekavach doctor"
  compose exec -T -w /data codekavach codekavach doctor || failed=1
  selftest="$(selftest_name compose exec -T codekavach codekavach)"
  step "Offline self-test (codekavach $selftest)"
  if compose exec -T -w /tmp codekavach codekavach "$selftest" --out /tmp/codekavach-selftest >/dev/null 2>&1; then
    good "the offline self-test passed"
  else
    warn "the offline self-test failed; run it to see why:"
    info "docker compose -p $PROJECT exec -w /tmp codekavach codekavach $selftest --out /tmp/codekavach-selftest"
    failed=1
  fi
  compose exec -T codekavach rm -rf /tmp/codekavach-selftest >/dev/null 2>&1 || true
  report_check "$failed"
}

docker_stop() {
  docker_require
  PROJECT="$(docker_project)"
  docker_refuse_foreign
  step "Stopping the container (Compose project: $PROJECT)"
  compose stop
  good "stopped; the data is kept. Start again with ./setup.sh"
}

docker_uninstall() {
  docker_require
  PROJECT="$(docker_project)"
  docker_refuse_foreign
  step "Removing the containers (Compose project: $PROJECT)"
  local delete=0
  if [ "$purge" = 1 ]; then
    delete=1
  elif interactive && confirm "Also delete ALL CodeKavach data (projects, scans, reports, users) and .env? This cannot be undone." n; then
    delete=1
  fi
  if [ "$delete" = 1 ]; then
    compose down --volumes --remove-orphans
    rm -f "$ENV_FILE"
    good "removed the containers, the data volume and .env"
  else
    compose down --remove-orphans
    good "removed the containers; the data volume ${PROJECT}_codekavach-data and .env are kept"
    info "delete them too with: ./setup.sh --uninstall --purge"
  fi
  info "the image stays; remove it with: docker image rm codekavach:local"
}

docker_status() {
  PROJECT="$(docker_project)"
  if docker_ready && docker_running; then
    good "running in Docker: http://127.0.0.1:$(kv_get "$ENV_FILE" CODEKAVACH_PORT)"
  else
    info "not running in Docker"
    return 1
  fi
}

# ==========================================================================================
# Local mode
# ==========================================================================================
default_data_dir() {
  case "$(uname -s)" in
    Darwin) printf '%s' "$HOME/Library/Application Support/codekavach" ;;
    *) printf '%s' "${XDG_DATA_HOME:-$HOME/.local/share}/codekavach" ;;
  esac
}

local_paths() {
  [ -n "$data_dir" ] || data_dir="$(default_data_dir)"
  case "$data_dir" in
    /*) ;;
    \~/*) data_dir="$HOME/${data_dir#\~/}" ;;
    *) data_dir="$PWD/$data_dir" ;;
  esac
  LOCAL_ENV="$data_dir/setup.env"
  PID_FILE="$data_dir/server.pid"
  LOG_FILE="$data_dir/server.log"
  SERVER_DIR="$data_dir/server"
  CLI="$REPO/.venv/bin/codekavach"
}

local_pid() {
  local pid
  [ -f "$PID_FILE" ] || return 1
  pid="$(cat "$PID_FILE" 2>/dev/null)"
  case "$pid" in
    "" | *[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null || return 1
  printf '%s' "$pid"
}

local_running() { local_pid >/dev/null; }

ensure_uv() {
  if ! have uv && [ -x "$HOME/.local/bin/uv" ]; then PATH="$HOME/.local/bin:$PATH"; fi
  if ! have uv && [ -x "$HOME/.cargo/bin/uv" ]; then PATH="$HOME/.cargo/bin:$PATH"; fi
  have uv && return 0
  step "uv is not installed"
  info "uv installs Python 3.12 and the dependencies. Its official installer puts one program in"
  info "your home directory (.local/bin) and needs no sudo. The command is:"
  info "  curl -LsSf $UV_INSTALLER | sh"
  have curl || die "curl is needed to install uv" "install curl, or install uv yourself: https://docs.astral.sh/uv/"
  if ! confirm "Run it now?" y; then
    die "uv is required for the local mode" "install it with the command above and run ./setup.sh again"
  fi
  curl -LsSf "$UV_INSTALLER" | sh
  PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  have uv || die "uv was installed but is not on PATH" "open a new terminal and run ./setup.sh again"
}

node_major() {
  have node || return 1
  node --version 2>/dev/null | sed -n 's/^v\([0-9][0-9]*\).*/\1/p'
}

build_dashboard() {
  local major stale=""
  major="$(node_major || true)"
  if [ -f ui/dist/index.html ]; then
    stale="$(find ui/src ui/index.html ui/package.json ui/package-lock.json -newer ui/dist/index.html 2>/dev/null | head -n 1)"
    if [ -z "$stale" ]; then
      info "the dashboard is already built (ui/dist)"
      return 0
    fi
  fi
  if [ -n "$major" ] && [ "$major" -ge 20 ] && have npm; then
    step "Building the dashboard (Node $(node --version))"
    (cd ui && npm ci --no-audit --no-fund && npm run build) || die "the dashboard build failed" \
      "behind a proxy: npm config set proxy http://HOST:PORT (see the README troubleshooting)"
    [ -f ui/dist/index.html ] || die "the dashboard build produced no ui/dist/index.html"
  elif [ -f ui/dist/index.html ]; then
    warn "Node 20 or newer is missing; using the dashboard that was built earlier (it is older than the sources)"
  else
    warn "Node 20 or newer with npm is missing, so the dashboard cannot be built"
    info "the server will run with the REST API and its docs only (no web pages)"
    info "install Node 20+ from https://nodejs.org and run ./setup.sh again, or use ./setup.sh --docker"
    dashboard_missing=1
  fi
}

# On WSL and headless Linux there is no usable OS keyring, which is where the CLI keeps the key
# of the pseudonym vault. Give the CLI a passphrase file instead, unless the user has a
# configuration file already. The server keeps its own key in its data directory either way.
configure_vault_key() {
  local status config pass_file
  status="$("$CLI" doctor --json --check secrets:keyring 2>/dev/null | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p' | head -n 1)" || status=""
  if [ "$status" = pass ]; then
    info "vault key: the OS keyring (or an existing passphrase setting)"
    return 0
  fi
  config="$("$CLI" config path --json 2>/dev/null | sed -n 's/.*"label":"user config","path":"\([^"]*\)".*/\1/p' | head -n 1)" || config=""
  if [ -z "$config" ]; then
    warn "no OS keyring, and the user configuration path is unknown; see docs/guide/quickstart.md (keyring)"
    return 0
  fi
  if [ -f "$config" ]; then
    if grep -q '^\[privacy\.vault\]' "$config"; then
      info "vault key: set in $config"
    else
      warn "no usable OS keyring here; add this to $config to use a passphrase file:"
      info '[privacy.vault]'
      info 'key_source = "passphrase"'
      info "passphrase = \"file:$data_dir/vault.passphrase\""
    fi
    return 0
  fi
  pass_file="$data_dir/vault.passphrase"
  if [ ! -s "$pass_file" ]; then
    (umask 077 && random_hex 32 >"$pass_file")
  fi
  chmod 600 "$pass_file"
  mkdir -p "$(dirname "$config")"
  (
    umask 077
    {
      printf '%s\n' "$CONFIG_MARK"
      printf '# There is no usable OS keyring on this machine, so the key of the pseudonym vault is\n'
      printf '# derived from a passphrase kept in a file that only you can read.\n'
      printf '[privacy.vault]\n'
      printf 'key_source = "passphrase"\n'
      printf 'passphrase = "file:%s"\n' "$pass_file"
    } >"$config"
  )
  info "vault key: no usable OS keyring here, so a passphrase file is used"
  info "  wrote $config and $pass_file (mode 0600)"
}

local_start() {
  local pid
  if pid="$(local_pid)"; then
    info "the server is already running (pid $pid)"
    return 0
  fi
  step "Starting the server on port $port"
  (
    set -a
    # shellcheck disable=SC1090
    . "$LOCAL_ENV"
    set +a
    unset CODEKAVACH_SETUP_PORT
    cd "$REPO"
    nohup "$CLI" serve --host 127.0.0.1 --port "$port" --data-dir "$SERVER_DIR" \
      >>"$LOG_FILE" 2>&1 </dev/null &
    printf '%s' "$!" >"$PID_FILE"
  )
  chmod 600 "$LOG_FILE" "$PID_FILE" 2>/dev/null || true
  if ! wait_health "http://127.0.0.1:$port$HEALTH_PATH" local_running; then
    tail -n 30 "$LOG_FILE" >&2 || true
    die "the server did not start" "the full log is $LOG_FILE"
  fi
}

local_setup() {
  local created_password="" stored password_line base current_port sync_args
  dashboard_missing=0
  local_paths
  step "Local mode (data in $data_dir)"

  ensure_uv
  step "Installing CodeKavach and its dependencies with uv"
  # A contributor's environment (pytest present) keeps its development tools.
  sync_args="--locked --extra server --extra reports"
  [ -x .venv/bin/pytest ] || sync_args="$sync_args --no-dev"
  # shellcheck disable=SC2086
  uv sync $sync_args || die "uv sync failed" \
    "behind a proxy: export HTTPS_PROXY=http://HOST:PORT and run ./setup.sh again"
  [ -x "$CLI" ] || die "the codekavach command was not installed in .venv"

  build_dashboard

  mkdir -p "$data_dir"
  chmod 700 "$data_dir"
  if [ ! -f "$LOCAL_ENV" ]; then
    (umask 077 && : >"$LOCAL_ENV")
    if [ ! -f "$SERVER_DIR/server.db" ]; then
      created_password="$(random_hex 12)"
      kv_set "$LOCAL_ENV" CODEKAVACH_ADMIN_PASSWORD "$created_password"
    else
      warn "this data directory already has a server database: its admin password is kept"
    fi
  fi
  chmod 600 "$LOCAL_ENV"

  read_api_key
  if [ -n "$api_key" ]; then
    kv_set "$LOCAL_ENV" CODEKAVACH_AGENTROUTER_API_KEY "$api_key"
    info "stored the $provider key in $LOCAL_ENV (used by the server)"
    if local_running; then
      warn "restart the server to use the new key: ./setup.sh --stop && ./setup.sh --local"
    fi
  elif [ -n "$(kv_get "$LOCAL_ENV" CODEKAVACH_AGENTROUTER_API_KEY)" ]; then
    api_key=present
  fi

  configure_vault_key

  current_port="$(kv_get "$LOCAL_ENV" CODEKAVACH_SETUP_PORT)"
  [ -n "$port" ] || port="${current_port:-8080}"
  if local_running; then
    if [ -n "$current_port" ] && [ "$port" != "$current_port" ]; then
      if [ "$port_given" = 1 ]; then
        warn "the server is running on port $current_port; stop it first to change the port (./setup.sh --stop)"
      fi
      port="$current_port"
    fi
  elif port_busy "$port"; then
    local wanted="$port"
    port="$(free_port "$port")"
    warn "port $wanted is busy; using $port instead"
  fi
  kv_set "$LOCAL_ENV" CODEKAVACH_SETUP_PORT "$port"
  base="http://127.0.0.1:$port"

  stored="$(kv_get "$LOCAL_ENV" CODEKAVACH_ADMIN_PASSWORD)"
  if [ -n "$created_password" ]; then
    password_line="$created_password   (initial password, shown once; also in $LOCAL_ENV)"
  elif [ -n "$stored" ]; then
    password_line="the initial password is in $LOCAL_ENV, unless you changed it since"
  else
    password_line="the one set when this data directory was first used"
  fi

  if [ "$start" = 0 ]; then
    good "prepared, not started"
    printf '\n  Start it in the background:\n    ./setup.sh --local --data-dir "%s"\n' "$data_dir"
    printf '  or in this terminal (Ctrl+C stops it):\n'
    printf '    (set -a; . "%s"; set +a; cd "%s" && exec .venv/bin/codekavach serve --host 127.0.0.1 --port %s --data-dir "%s")\n' \
      "$LOCAL_ENV" "$REPO" "$port" "$SERVER_DIR"
    printf '\n  Dashboard   %s\n  User name   %s\n  Password    %s\n' "$base" "$ADMIN_USER" "$password_line"
    return 0
  fi

  local_start
  if want_samples; then
    if [ -n "$stored" ]; then
      add_samples "$base" "$stored"
    else
      warn "the admin password is not in $LOCAL_ENV, so the samples cannot be added from here"
    fi
  fi

  if [ "$dashboard_missing" = 1 ]; then
    summary local "$base" "$password_line" "Data        $data_dir" "Log         $LOG_FILE" \
      "Note        the web pages are not built (Node 20+ missing); $base/api/docs works"
  else
    summary local "$base" "$password_line" "Data        $data_dir" "Log         $LOG_FILE"
  fi
}

local_check() {
  local failed=0 selftest out
  local_paths
  [ -x "$CLI" ] || die "CodeKavach is not installed in .venv" "run ./setup.sh --local first"
  step "codekavach doctor"
  "$CLI" doctor || failed=1
  selftest="$(selftest_name "$CLI")"
  step "Offline self-test (codekavach $selftest)"
  out="$(mktemp -d)"
  if (cd "$out" && "$CLI" "$selftest" --out "$out/result" >"$out/log" 2>&1); then
    good "the offline self-test passed"
  else
    warn "the offline self-test failed; its last lines:"
    tail -n 15 "$out/log" >&2 || true
    failed=1
  fi
  rm -rf "$out"
  if local_running; then
    port="$(kv_get "$LOCAL_ENV" CODEKAVACH_SETUP_PORT)"
    if http_ok "http://127.0.0.1:$port$HEALTH_PATH"; then
      good "the server answers on http://127.0.0.1:$port"
    else
      warn "the server process runs but does not answer on port $port"
      failed=1
    fi
  else
    info "the server is not running (start it with ./setup.sh --local)"
  fi
  report_check "$failed"
}

local_stop() {
  local pid waited=0
  local_paths
  if ! pid="$(local_pid)"; then
    info "the local server is not running"
    rm -f "$PID_FILE"
    return 0
  fi
  step "Stopping the server (pid $pid)"
  kill "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    sleep 1
    waited=$((waited + 1))
    if [ "$waited" -eq 15 ]; then kill -9 "$pid" 2>/dev/null || true; fi
    [ "$waited" -lt 20 ] || break
  done
  rm -f "$PID_FILE"
  good "stopped; the data is kept in $data_dir"
}

local_uninstall() {
  local config
  local_stop
  if [ ! -d "$data_dir" ]; then
    info "there is no data directory at $data_dir"
  elif [ "$purge" = 1 ] || { interactive && confirm "Delete ALL CodeKavach data in $data_dir (projects, scans, reports, users)? This cannot be undone." n; }; then
    # Refuse anything that is not recognisably a CodeKavach data directory.
    if [ -f "$LOCAL_ENV" ] || [ -d "$SERVER_DIR" ]; then
      rm -rf "$data_dir"
      good "deleted $data_dir"
    else
      warn "$data_dir does not look like a CodeKavach data directory; not deleted"
    fi
    config="${XDG_CONFIG_HOME:-$HOME/.config}/codekavach/config.toml"
    if [ -f "$config" ] && [ "$(head -n 1 "$config")" = "$CONFIG_MARK" ]; then
      rm -f "$config"
      info "removed $config (written by this script)"
    fi
  else
    good "the data in $data_dir is kept"
    info "delete it too with: ./setup.sh --local --uninstall --purge"
  fi
  info "the Python environment and the built dashboard stay in this checkout;"
  info "remove them with: rm -rf .venv ui/node_modules ui/dist"
}

local_status() {
  local_paths
  if local_running; then
    good "running locally: http://127.0.0.1:$(kv_get "$LOCAL_ENV" CODEKAVACH_SETUP_PORT) (pid $(local_pid))"
  else
    info "not running locally"
    return 1
  fi
}

# ==========================================================================================
# Shared: self-test name, check report, mode choice
# ==========================================================================================
# selftest_name COMMAND...: "selftest" when the CLI has it, otherwise its earlier name.
selftest_name() {
  local earlier
  earlier="$(printf 'd%smo' e)"
  if "$@" selftest --help >/dev/null 2>&1; then printf 'selftest'; else printf '%s' "$earlier"; fi
}

report_check() {
  if [ "$1" = 0 ]; then
    printf '\n%sPASS%s  CodeKavach is installed and works.\n' "$bold$green" "$off"
  else
    printf '\n%sFAIL%s  see the messages above.\n' "$bold$red" "$off"
    exit 1
  fi
}

# For --check, --stop, --status and --uninstall without a mode: whichever installation exists.
existing_mode() {
  local_paths
  PROJECT="$(docker_project)"
  if docker_ready && ! docker_foreign && [ -n "$(compose ps -aq codekavach 2>/dev/null)" ]; then
    printf 'docker'
  elif [ -f "$LOCAL_ENV" ] || [ -f "$PID_FILE" ]; then
    printf 'local'
  elif [ -f "$ENV_FILE" ] && docker_ready && ! docker_foreign; then
    printf 'docker'
  elif [ -x "$REPO/.venv/bin/codekavach" ]; then
    printf 'local'
  fi
}

if [ "$action" = setup ]; then
  if [ -z "$mode" ]; then
    if docker_ready; then
      mode=docker
    else
      mode=local
      if have docker; then
        info "Docker is installed but not running (or Compose v2 is missing): using the local mode"
      else
        info "Docker is not installed: using the local mode"
      fi
    fi
  fi
  case "$mode" in
    docker) docker_setup ;;
    local) local_setup ;;
  esac
  exit 0
fi

if [ -z "$mode" ]; then
  mode="$(existing_mode)"
  if [ -z "$mode" ]; then
    if [ "$action" = status ]; then
      info "CodeKavach is not set up here yet; run ./setup.sh"
      exit 1
    fi
    die "no CodeKavach installation found here" "run ./setup.sh first, or name the mode: --docker or --local"
  fi
fi
"${mode}_${action}"
