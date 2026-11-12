# syntax=docker/dockerfile:1.7
#
# CodeKavach server image (E39-02): API server + web dashboard + CLI in one image.
#
#   docker build -f deploy/docker/Dockerfile -t codekavach:local .
#   docker run --rm -p 8080:8080 -v ck-data:/data codekavach:local
#
# Stages
#   uv       the pinned uv binary
#   ui       node 22 builds the dashboard (ui/ -> ui/dist) with `npm ci && npm run build`
#   python   uv installs the locked dependencies (extras: server, reports) into /app/.venv
#   engines  fetches the pinned Opengrep binary and checks its sha256
#   runtime  python 3.12 slim + WeasyPrint system libraries, non-root user, no compiler
#
# Every base is pinned by digest; the readable tag is in the comment above it. Refresh the pins
# with deploy/docker/refresh-digests.sh and review the diff.
#
# The image never contains a secret: provider keys and the admin password are passed at run time
# (see .env.example). The build context is filtered by .dockerignore, which is a privacy control:
# state directories, vaults, ledgers and .env files must never reach a layer.

# node:22-bookworm-slim
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
# python:3.12-slim-bookworm
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
# ghcr.io/astral-sh/uv:0.13.8
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85

FROM ${UV_IMAGE} AS uv

# --------------------------------------------------------------------------------------------
# Stage: the dashboard
# --------------------------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS ui
WORKDIR /ui
ENV npm_config_fund=false npm_config_audit=false npm_config_update_notifier=false \
    DO_NOT_TRACK=1
COPY ui/ ./
# The dashboard contract: ui/package.json has a "build" script that writes ui/dist. A checkout
# without the dashboard still builds an image (API and CLI work); the page says so.
RUN set -eu; \
    if [ -f package.json ]; then \
        if [ -f package-lock.json ]; then npm ci; else npm install; fi; \
        npm run build; \
        test -f dist/index.html; \
    else \
        mkdir -p dist; \
        printf '%s\n' '<!doctype html><meta charset="utf-8"><title>CodeKavach</title>' \
          '<body style="font-family:sans-serif;max-width:40rem;margin:4rem auto">' \
          '<h1>CodeKavach API is running</h1><p>This image was built without the web dashboard ' \
          '(ui/package.json was absent). The REST API is at <code>/api/v1</code>.</p>' > dist/index.html; \
    fi

# --------------------------------------------------------------------------------------------
# Stage: the Python environment
# --------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS python
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
# Dependencies first (cached while only the source changes), then the project itself.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project --extra server --extra reports
COPY src ./src
# The wheel force-includes data/ as codekavach/data (pyproject.toml), so the build needs it here.
COPY data ./data
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra server --extra reports
# Bandit (Apache-2.0) is listed as a client-installed engine; the image ships the pinned version so
# the analyse-engines stage can use it. Build with --build-arg BANDIT_VERSION= to omit it.
ARG BANDIT_VERSION=1.9.4
RUN --mount=type=cache,target=/root/.cache/uv \
    if [ -n "${BANDIT_VERSION}" ]; then \
        uv pip install --python /app/.venv/bin/python "bandit==${BANDIT_VERSION}"; \
    fi

# --------------------------------------------------------------------------------------------
# Stage: pinned engine binaries
# --------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS engines
ARG TARGETARCH
# Opengrep (LGPL-2.1) runs as a separate process and is never linked, so shipping the unmodified
# release binary is permitted (docs/research/INSIGHTS.md section 5). Build with
# --build-arg OPENGREP_VERSION= to leave it out; the engine is then reported as unavailable.
ARG OPENGREP_VERSION=1.33.1
ARG OPENGREP_SHA256_AMD64=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
ARG OPENGREP_SHA256_ARM64=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf
RUN set -eu; mkdir -p /engines; \
    if [ -n "${OPENGREP_VERSION}" ]; then \
        case "${TARGETARCH:-amd64}" in \
            amd64) asset=opengrep_manylinux_x86; sum="${OPENGREP_SHA256_AMD64}";; \
            arm64) asset=opengrep_manylinux_aarch64; sum="${OPENGREP_SHA256_ARM64}";; \
            *) echo "no Opengrep build for ${TARGETARCH}" >&2; exit 1;; \
        esac; \
        python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/engines/opengrep')" \
            "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${asset}"; \
        echo "${sum}  /engines/opengrep" | sha256sum -c -; \
        chmod 0755 /engines/opengrep; \
    fi

# --------------------------------------------------------------------------------------------
# Stage: runtime
# --------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
ARG VERSION=0.1.0.dev0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="CodeKavach" \
      org.opencontainers.image.description="Privacy-preserving, LLM-assisted secure source code review: API server, web dashboard and CLI" \
      org.opencontainers.image.source="https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT"

# WeasyPrint runtime (PDF reports), fonts, git (projects with a git source) and tini (PID 1).
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libharfbuzz0b \
        fonts-dejavu-core fonts-liberation \
        git ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 codekavach \
    && useradd --system --uid 10001 --gid codekavach --home-dir /data --shell /usr/sbin/nologin codekavach \
    && mkdir -p /data \
    && chown codekavach:codekavach /data \
    && chmod 0700 /data

WORKDIR /app
# The checkout layout is kept (src/, rules/, data/, fixtures/kavachbank, docs/schemas, ui/dist)
# because rule packs, schemas, the sample project and replay cassettes are located relative to it.
COPY --from=python /app /app
COPY --from=engines /engines/ /usr/local/bin/
COPY rules ./rules
COPY data ./data
COPY docs/schemas ./docs/schemas
COPY fixtures/kavachbank ./fixtures/kavachbank
COPY --from=ui /ui/dist ./ui/dist

# CODEKAVACH_HOME holds the user configuration and consent state. The vault key comes from a
# passphrase (there is no OS keyring in a container); the passphrase itself is only a reference
# here and its value is passed at run time as CODEKAVACH_VAULT_PASSPHRASE.
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DO_NOT_TRACK=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    HOME=/data \
    CODEKAVACH_HOME=/data/home \
    CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE=passphrase \
    CODEKAVACH_PRIVACY__VAULT__PASSPHRASE=env:CODEKAVACH_VAULT_PASSPHRASE \
    XDG_CACHE_HOME=/data/cache

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["/usr/bin/tini", "--", "codekavach"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080", "--data-dir", "/data"]
