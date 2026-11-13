"""GitHub issue sync for server scans, through the E34 back end.

Owning epic: E32.

The server passes the scan's findings, with their triage status, to
``codekavach.integrations.github.sync.sync_findings``. The token is accepted only as a secret
reference (``env:``, ``file:``, ``keyring:``) so no credential travels in a request body or lands
in the database, and only a reference the server allows (``ServerConfig.github_token_refs``) so a
caller cannot make the server resolve, probe or send any other secret; without one the result is a
dry-run plan. When the back end is not installed the
route answers 501 ``backend_unavailable`` instead of an empty success.
"""

from collections.abc import Sequence
from typing import Any, Final

from codekavach.core.log import get_logger
from codekavach.server.errors import ApiError

_log = get_logger("codekavach.server.github")
REFERENCE_PREFIXES: Final = ("env:", "file:", "keyring:")


def sync_scan(
    findings: Sequence[Any],
    *,
    repo: str,
    token_ref: str | None,
    dry_run: bool,
    allowed_refs: Sequence[str] = (),
) -> dict[str, Any]:
    """Plan or apply the issue sync of ``findings`` (``FindingRow`` objects)."""
    if token_ref and not token_ref.startswith(REFERENCE_PREFIXES):
        raise ApiError(
            400,
            "token_not_reference",
            "pass the GitHub token as a reference such as env:GITHUB_TOKEN, never the token",
        )
    if token_ref and token_ref not in allowed_refs:
        raise ApiError(
            400,
            "token_ref_not_allowed",
            f"the token reference must be one of {', '.join(allowed_refs) or '(none)'}",
            hint="an admin sets the allowed references in the server configuration",
        )
    if not dry_run and not token_ref:
        raise ApiError(400, "token_required", "a token reference is needed to change issues")
    notes: list[str] = []
    if token_ref and not _reference_resolves(token_ref):
        if not dry_run:
            raise ApiError(
                400,
                "token_unresolved",
                f"the token reference {token_ref} is not set on the server",
                hint="set it in the server's environment, or preview with a dry run",
            )
        # A preview needs no token: plan as if the repository had no CodeKavach issues yet.
        notes.append(f"{token_ref} is not set on the server: existing issues were not read")
        token_ref = None
    try:
        from codekavach.integrations.github.sync import sync_findings  # noqa: PLC0415
    except ImportError:
        raise ApiError(
            501, "backend_unavailable", "the GitHub integration is not installed"
        ) from None
    items = []
    for row in findings:
        data = dict(row.data or {})
        data["status"] = row.status
        items.append(data)
    try:
        result = sync_findings({"findings": items}, repo, token_ref, dry_run=dry_run)
    except ApiError:
        raise
    except Exception as error:  # noqa: BLE001 - reported as a gateway error, never a trace
        _log.warning("server_github_sync_failed", error_type=type(error).__name__)
        raise ApiError(
            502, "github_sync_failed", f"the GitHub sync failed: {type(error).__name__}"
        ) from None
    out = dict(result)
    if notes:
        rest = [n for n in out.get("notes") or [] if not str(n).startswith("no token")]
        out["notes"] = [*notes, *rest]
    return out


def _reference_resolves(reference: str) -> bool:
    """Whether a secret reference has a value here; the value itself is not kept."""
    from codekavach.config.errors import SecretResolutionError  # noqa: PLC0415
    from codekavach.config.keys import resolve_secret  # noqa: PLC0415

    try:
        return bool(resolve_secret(reference).get_secret_value())
    except SecretResolutionError:
        return False
