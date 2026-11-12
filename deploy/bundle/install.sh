#!/usr/bin/env bash
# Offline installer of the CodeKavach air-gapped bundle (E39-02). Reads only this directory.
#
#   ./install.sh                 docker mode (default): load the image, write compose files
#   ./install.sh --pip [PREFIX]  pip mode: a virtual environment at PREFIX (default
#                                ~/.local/share/codekavach/venv) installed with --no-index
#   ./install.sh --verify        only check SHA256SUMS
#
# Every file is checked against SHA256SUMS first; a mismatch stops the install.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="docker"
PREFIX="${HOME}/.local/share/codekavach/venv"
case "${1:-}" in
    --pip) MODE="pip"; PREFIX="${2:-${PREFIX}}" ;;
    --verify) MODE="verify" ;;
    --docker|"") ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

cd "${HERE}"
echo "==> verifying bundle contents"
sha256sum --quiet -c SHA256SUMS
echo "    all files match SHA256SUMS"
[ "${MODE}" = verify ] && exit 0

if [ "${MODE}" = docker ]; then
    command -v docker >/dev/null || { echo "docker is not installed; use --pip" >&2; exit 1; }
    echo "==> loading the image"
    gunzip -c image/codekavach-image.tar.gz | docker load
    TARGET="${CODEKAVACH_INSTALL_DIR:-${HOME}/codekavach}"
    mkdir -p "${TARGET}"
    cp compose/docker-compose.yml "${TARGET}/docker-compose.yml"
    if [ ! -f "${TARGET}/.env" ]; then
        cp compose/.env.example "${TARGET}/.env"
        chmod 0600 "${TARGET}/.env"
        # Air-gapped default: no remote provider key, a random vault passphrase.
        passphrase="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        sed -i "s/^CODEKAVACH_VAULT_PASSPHRASE=.*/CODEKAVACH_VAULT_PASSPHRASE=${passphrase}/" "${TARGET}/.env"
        echo "CODEKAVACH_IMAGE=$(cat image/IMAGE)" >> "${TARGET}/.env"
    fi
    cat <<EOF

Installed. Next steps:
  cd ${TARGET}
  edit .env (set CODEKAVACH_ADMIN_PASSWORD)
  docker compose up -d --no-build codekavach     # dashboard on http://127.0.0.1:8080
  # strictly no network:   docker compose --profile airgapped up -d --no-build codekavach-airgapped
Offline providers: mock, replay, or a local Ollama model (profile local-llm, weights copied separately).
EOF
    exit 0
fi

PY="${PYTHON:-python3.12}"
command -v "${PY}" >/dev/null || PY=python3
"${PY}" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 12) else 1)' \
    || { echo "Python 3.12 or newer is required" >&2; exit 1; }
echo "==> creating ${PREFIX}"
"${PY}" -m venv "${PREFIX}"
"${PREFIX}/bin/python" -m pip install --quiet --no-index --find-links wheels --require-hashes \
    -r wheels/requirements.txt
"${PREFIX}/bin/python" -m pip install --quiet --no-index --no-deps wheels/codekavach-*.whl
STATE="${CODEKAVACH_HOME:-${HOME}/.config/codekavach}"
mkdir -p "${STATE}" && chmod 0700 "${STATE}"
cat <<EOF

Installed ${PREFIX}/bin/codekavach. Next steps:
  export PATH=${PREFIX}/bin:\$PATH
  codekavach doctor --offline
  codekavach scan ${HERE}/fixtures/kavachbank --provider mock --profile airgapped
EOF
