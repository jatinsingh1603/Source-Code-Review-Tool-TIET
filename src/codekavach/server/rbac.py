"""Roles, permissions and the permission matrix of the REST API.

Owning epic: E32.

Every authenticated route declares one ``Permission`` through ``require``; the matrix below is the
only place that says which role holds it. ``auditor`` may read the original-versus-sent pairs of
the egress ledger (``privacy:read_original``); ``developer`` may run scans and triage findings but
not read originals; ``viewer`` reads results only.
"""

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class Role(StrEnum):
    """The four server roles."""

    admin = "admin"
    auditor = "auditor"
    developer = "developer"
    viewer = "viewer"


class Permission(StrEnum):
    """What a route needs."""

    read = "read"
    project_write = "project:write"
    scan_run = "scan:run"
    finding_triage = "finding:triage"
    report_read = "report:read"
    ledger_read = "privacy:read_ledger"
    original_read = "privacy:read_original"
    provider_test = "provider:test"
    settings_write = "settings:write"
    users_admin = "users:admin"
    sync = "sync:github"
    audit_read = "audit:read"


_ALL = frozenset(Permission)
_DEVELOPER = frozenset(
    {
        Permission.read,
        Permission.project_write,
        Permission.scan_run,
        Permission.finding_triage,
        Permission.report_read,
        Permission.ledger_read,
        Permission.provider_test,
        Permission.sync,
    }
)
_AUDITOR = _DEVELOPER | {Permission.original_read, Permission.audit_read}
_VIEWER = frozenset({Permission.read, Permission.report_read})

PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.admin: _ALL,
        Role.auditor: frozenset(_AUDITOR),
        Role.developer: _DEVELOPER,
        Role.viewer: _VIEWER,
    }
)


def permitted(role: str, permission: Permission) -> bool:
    """Whether ``role`` holds ``permission`` (an unknown role holds nothing)."""
    try:
        return permission in PERMISSIONS[Role(role)]
    except ValueError:
        return False
