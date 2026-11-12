#!/usr/bin/env bash
# Re-pin the base images of deploy/docker/Dockerfile to the current digest of their tag.
# A base update is then a reviewable one-line diff per image.
set -euo pipefail
FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Dockerfile"
for ref in node:22-bookworm-slim python:3.12-slim-bookworm ghcr.io/astral-sh/uv:0.13.8; do
    docker pull --quiet "${ref}" >/dev/null
    digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "${ref}" | sed 's/.*@//')"
    name="${ref%%:*}"
    tag="${ref#*:}"
    # Rewrite "<name>:<tag>@sha256:<old>" to the new digest, wherever it occurs.
    sed -i -E "s#(${name//\//\\/}:${tag})@sha256:[0-9a-f]{64}#\1@${digest}#g" "${FILE}"
    echo "${ref} -> ${digest}"
done
git --no-pager diff --stat -- "${FILE}" || true
