"""Configuration for the KavachBank API service.

DELIBERATELY INSECURE SAMPLE: every credential below is synthetic and is listed in
ground-truth/manifest.yaml. Nothing here is a working secret.
"""

import os

ENVIRONMENT = os.environ.get("KB_ENV", "development")
EXPORT_DIR = os.environ.get("KB_EXPORT_DIR", "/var/lib/kavachbank/exports")
SESSION_TTL_MINUTES = 30
ALLOWED_PARTNER_HOSTS = frozenset({"rates.partner-bank.example", "kyc.partner-bank.example"})

DATABASE_URL = "postgres://svc:AKIAIOSFODNN7EXAMPLE@db.internal/app"

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
RAZORPAY_KEY_SECRET = "abcdefghijklmnopqrstuvwx"
JWT_SIGNING_SECRET = "hunter2hunter2"
SIGNING_KEY_PEM = """-----BEGIN PRIVATE KEY-----
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/
bcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/a
cdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/ab
defghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abc
-----END PRIVATE KEY-----"""
