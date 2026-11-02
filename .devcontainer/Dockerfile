# Development container for CodeKavach (E01-29). Debian bookworm, Python 3.12, uv, make, git and
# the WeasyPrint runtime libraries (E31). Runs as the non-root vscode user; nothing is privileged
# and no credentials are baked in. Dependabot (docker ecosystem) keeps the pins current.
# devcontainer.json mounts nothing and holds no keys; the virtual environment lives outside the
# bind-mounted workspace (UV_PROJECT_ENVIRONMENT) so host and container never share one.

# mcr.microsoft.com/devcontainers/python:3.12-bookworm
FROM mcr.microsoft.com/devcontainers/python:3.15-bookworm@sha256:25ac34e3c1a4c5b19a89ece73ed0278e92afc1cfd25ecb51714891e82bede421

# Static uv binaries from the official image; no piped shell installer.
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /uvx /bin/

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        make \
        git \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz-subset0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

USER vscode
