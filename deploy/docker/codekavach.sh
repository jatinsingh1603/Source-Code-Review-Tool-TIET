#!/bin/sh
# Container front for the codekavach command (E39-02).
#
# A container has no OS keyring, so the vault key comes from a passphrase. The server keeps that
# passphrase in <data dir>/vault.passphrase (mode 0600) unless CODEKAVACH_SERVER_VAULT_PASSPHRASE
# is set. This wrapper gives every codekavach process in the container, the server and a CLI run
# through `docker compose exec`, the same passphrase, so a vault written by one opens in the other.
set -eu
if [ -z "${CODEKAVACH_SERVER_VAULT_PASSPHRASE:-}" ]; then
    file="${CODEKAVACH_SERVER_DATA_DIR:-/data}/vault.passphrase"
    if [ ! -s "${file}" ] && [ -w "$(dirname "${file}")" ]; then
        (umask 077 && python -c "import secrets; print(secrets.token_hex(32), end='')" > "${file}")
    fi
    if [ -s "${file}" ]; then
        CODEKAVACH_SERVER_VAULT_PASSPHRASE="$(cat "${file}")"
        export CODEKAVACH_SERVER_VAULT_PASSPHRASE
    fi
fi
exec /app/.venv/bin/codekavach "$@"
