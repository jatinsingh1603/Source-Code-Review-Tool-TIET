"""Shared values for tests that start the REST API server.

The server has no built-in admin password: a test names one. ``force_password_change`` is off
in most server tests so that the fixture accounts can call the API straight after signing in;
the first-sign-in flow has tests of its own (``tests/integration/server/test_first_admin.py``).
"""

from typing import Final

ADMIN_USER: Final = "admin"
ADMIN_PASSWORD: Final = "fixture-admin-password"  # pragma: allowlist secret
ADMIN: Final = {"username": ADMIN_USER, "password": ADMIN_PASSWORD}
