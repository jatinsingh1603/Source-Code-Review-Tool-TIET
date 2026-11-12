"""GitHub integration.

REST and GraphQL client, issue sync, Projects v2 sync, checks, SARIF upload and App webhooks.

Owning epic: E34. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.integrations.github.sync import run_github_sync, sync_findings

__all__ = ["run_github_sync", "sync_findings"]
