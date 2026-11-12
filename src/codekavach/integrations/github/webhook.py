"""GitHub App webhook verification and a handler skeleton.

Owning epic: E34.

``verify_signature`` checks ``X-Hub-Signature-256`` in constant time. ``handle_event`` maps an event
to the action CodeKavach would take; it does not scan or call GitHub itself. Registering the App
and hosting the endpoint is a human step (see ``action/README.md``).
"""

import hashlib
import hmac
from typing import Any


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    """True when ``header`` is the valid HMAC-SHA256 signature of ``body``."""
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


def handle_event(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Describe the review to start for ``event`` (``pull_request``, ``push``, ``ping``)."""
    repo = (payload.get("repository") or {}).get("full_name")
    if event == "ping":
        return {"action": "pong"}
    if event == "pull_request" and payload.get("action") in ("opened", "synchronize", "reopened"):
        pull = payload.get("pull_request") or {}
        return {
            "action": "scan",
            "repo": repo,
            "pull": pull.get("number"),
            "head_sha": (pull.get("head") or {}).get("sha"),
            "report": ["check_run", "review"],
        }
    if event == "push":
        return {
            "action": "scan",
            "repo": repo,
            "head_sha": payload.get("after"),
            "report": ["sarif"],
        }
    return {"action": "ignore", "event": event}
