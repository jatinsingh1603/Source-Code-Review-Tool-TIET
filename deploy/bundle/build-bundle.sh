#!/usr/bin/env bash
# Build the air-gapped bundle (E39-02) on a connected machine.
#
#   deploy/bundle/build-bundle.sh [--out DIR] [--image TAG] [--no-image] [--no-wheels]
#                                 [--platform manylinux_2_28_x86_64] [--python 3.12]
#
# The bundle holds everything CodeKavach needs at run time, so the target machine needs no
# network at all:
#   image/codekavach-image.tar.gz   `docker save` of the server image (dashboard, API, CLI,
#                                   Opengrep, Bandit, WeasyPrint libraries, rules, sample project)
#   wheels/                         the codekavach wheel and every locked dependency as wheels
#                                   for one platform and interpreter, plus requirements.txt with
#                                   hashes (for a pip install without Docker)
#   compose/                        docker-compose.yml and .env.example
#   rules/ data/ fixtures/kavachbank
#   install.sh                      the offline installer (docker or pip mode)
#   MANIFEST.json, SHA256SUMS       component list with sizes and sha256; install.sh checks them
#
# Models are never shipped. For a local model, pull permissively licensed weights on a connected
# machine (`ollama pull qwen2.5-coder:7b`) and copy the Ollama volume separately.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${ROOT}/deploy/bundle/out"
IMAGE="${CODEKAVACH_IMAGE:-codekavach:local}"
PLATFORM="manylinux_2_28_x86_64"
PYVER="3.12"
WITH_IMAGE=1
WITH_WHEELS=1
# python:3.12-slim-bookworm, used only to run `pip download` for the target platform.
PY_IMAGE="python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --image) IMAGE="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
        --python) PYVER="$2"; shift 2 ;;
        --no-image) WITH_IMAGE=0; shift ;;
        --no-wheels) WITH_WHEELS=0; shift ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

cd "${ROOT}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)"
NAME="codekavach-airgapped-${VERSION}"
STAGE="${OUT}/${NAME}"
rm -rf -- "${STAGE:?}"
mkdir -p "${STAGE}"/{image,wheels,compose,fixtures}
echo "==> bundle ${NAME} in ${STAGE}"

if [ "${WITH_IMAGE}" = 1 ]; then
    if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
        echo "==> building ${IMAGE}"
        docker build --network host -f deploy/docker/Dockerfile -t "${IMAGE}" .
    fi
    echo "==> saving ${IMAGE}"
    docker save "${IMAGE}" | gzip -6 > "${STAGE}/image/codekavach-image.tar.gz"
    echo "${IMAGE}" > "${STAGE}/image/IMAGE"
fi

if [ "${WITH_WHEELS}" = 1 ]; then
    echo "==> resolving wheels for ${PLATFORM} / CPython ${PYVER}"
    uv export --locked --no-dev --no-emit-project --extra server --extra reports \
        --format requirements-txt > "${STAGE}/wheels/requirements.txt"
    uv build --wheel --out-dir "${STAGE}/wheels" >/dev/null
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "${STAGE}/wheels:/w" "${PY_IMAGE}" \
        python -m pip download --quiet --no-deps --only-binary=:all: --timeout 120 --retries 5 \
        --platform "${PLATFORM}" --platform manylinux2014_x86_64 --platform linux_x86_64 \
        --python-version "${PYVER}" --implementation cp \
        -r /w/requirements.txt -d /w
fi

echo "==> copying rules, data, sample project and compose files"
cp -r rules data "${STAGE}/"
cp -r fixtures/kavachbank "${STAGE}/fixtures/"
cp docker-compose.yml .env.example "${STAGE}/compose/"
cp deploy/bundle/install.sh "${STAGE}/install.sh"
chmod 0755 "${STAGE}/install.sh"

echo "==> writing MANIFEST.json and SHA256SUMS"
(
    cd "${STAGE}"
    find . -type f ! -name SHA256SUMS ! -name MANIFEST.json -print0 | sort -z \
        | xargs -0 sha256sum | sed 's#  \./#  #' > SHA256SUMS
    python3 - "${VERSION}" "${PLATFORM}" "${PYVER}" "${IMAGE}" <<'PY'
import json, os, sys, datetime
version, platform, pyver, image = sys.argv[1:5]
components = []
for line in open("SHA256SUMS", encoding="utf-8"):
    digest, path = line.rstrip("\n").split("  ", 1)
    mode = "bundled"
    licence = "MIT" if path.startswith(("rules/", "data/", "fixtures/", "compose/", "install.sh")) else None
    components.append({"path": path, "sha256": digest, "size": os.path.getsize(path),
                       "licence": licence, "mode": mode})
manifest = {"bundle_version": 1, "tool_version": version,
            "built": datetime.date.today().isoformat(), "interpreters": [pyver],
            "platforms": [platform], "image": image, "components": components}
json.dump(manifest, open("MANIFEST.json", "w", encoding="utf-8"), indent=2)
PY
)

echo "==> packing"
tar -C "${OUT}" -czf "${OUT}/${NAME}.tar.gz" "${NAME}"
( cd "${OUT}" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )
du -sh "${OUT}/${NAME}.tar.gz"
echo "bundle: ${OUT}/${NAME}.tar.gz"
echo "copy it with its .sha256 file to the offline machine, then:"
echo "  sha256sum -c ${NAME}.tar.gz.sha256 && tar xzf ${NAME}.tar.gz && ${NAME}/install.sh"
