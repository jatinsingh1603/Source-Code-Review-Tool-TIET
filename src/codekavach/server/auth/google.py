"""Google sign-in (OpenID Connect authorisation-code flow with PKCE). Off unless configured.

Owning epic: E32.

Nothing here runs unless ``CODEKAVACH_GOOGLE_CLIENT_ID`` and ``CODEKAVACH_GOOGLE_CLIENT_SECRET``
are both set. When they are, the server contacts ``oauth2.googleapis.com`` once per sign-in to
exchange the authorisation code. That is identity traffic about the person signing in: it carries
no source code, does not pass through the code egress transport and is not written to the egress
ledger. The client secret, the code and the tokens are never logged.

The ID token is read from the token endpoint's TLS response, which OpenID Connect Core 3.1.3.7
accepts in place of a signature check; issuer, audience, expiry, nonce and ``email_verified`` are
still checked.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlencode

from codekavach.server.rbac import Role

CLIENT_ID_ENV: Final = "CODEKAVACH_GOOGLE_CLIENT_ID"
CLIENT_SECRET_ENV: Final = "CODEKAVACH_GOOGLE_CLIENT_SECRET"  # noqa: S105 - a variable name
ALLOWED_DOMAINS_ENV: Final = "CODEKAVACH_GOOGLE_ALLOWED_DOMAINS"
ALLOWED_EMAILS_ENV: Final = "CODEKAVACH_GOOGLE_ALLOWED_EMAILS"
DEFAULT_ROLE_ENV: Final = "CODEKAVACH_GOOGLE_DEFAULT_ROLE"
PUBLIC_URL_ENV: Final = "CODEKAVACH_PUBLIC_URL"

AUTH_URL: Final = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL: Final = "https://oauth2.googleapis.com/token"  # noqa: S105 - an endpoint, not a secret
ISSUERS: Final = frozenset({"accounts.google.com", "https://accounts.google.com"})
CALLBACK_PATH: Final = "/api/v1/auth/google/callback"
STATE_COOKIE: Final = "ck_google_sso"
STATE_TTL_SECONDS: Final = 600
TOKEN_TIMEOUT_SECONDS: Final = 10.0
MAX_USERNAME: Final = 64
JWT_PARTS: Final = 3

# ``exchange(config, code, verifier, redirect_uri)`` returns the token endpoint's JSON.
Exchange = Callable[["GoogleSso", str, str, str], Mapping[str, Any]]


class SsoError(Exception):
    """A sign-in failure; ``code`` is the short reason shown to the browser, nothing more."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _env(environ: Mapping[str, str], name: str) -> str:
    """``name`` from the environment, or the content of the file named by ``name_FILE``."""
    value = environ.get(name, "").strip()
    if value:
        return value
    path = environ.get(f"{name}_FILE", "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def _items(value: str) -> tuple[str, ...]:
    return tuple(item.strip().lower() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class GoogleSso:
    """The Google sign-in settings of one server."""

    client_id: str
    client_secret: str
    allowed_domains: tuple[str, ...] = ()
    allowed_emails: tuple[str, ...] = ()
    default_role: str = Role.viewer.value
    public_url: str = ""

    def __repr__(self) -> str:
        """The settings without the secret, so a logged config cannot leak it."""
        return f"GoogleSso(client_id={self.client_id!r}, client_secret=<hidden>)"

    def allows(self, email: str) -> bool:
        """Whether ``email`` may sign in: anyone when no domain and no address is listed."""
        if not self.allowed_domains and not self.allowed_emails:
            return True
        address = email.lower()
        return address in self.allowed_emails or address.rpartition("@")[2] in self.allowed_domains


def from_env(environ: Mapping[str, str] | None = None) -> GoogleSso | None:
    """The settings from the environment; ``None`` (feature off) unless id and secret are set."""
    env = os.environ if environ is None else environ
    client_id = _env(env, CLIENT_ID_ENV)
    client_secret = _env(env, CLIENT_SECRET_ENV)
    if not client_id or not client_secret:
        return None
    role = env.get(DEFAULT_ROLE_ENV, "").strip().lower()
    return GoogleSso(
        client_id=client_id,
        client_secret=client_secret,
        allowed_domains=_items(env.get(ALLOWED_DOMAINS_ENV, "")),
        allowed_emails=_items(env.get(ALLOWED_EMAILS_ENV, "")),
        default_role=role if role in {item.value for item in Role} else Role.viewer.value,
        public_url=env.get(PUBLIC_URL_ENV, "").strip().rstrip("/"),
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _now(now: float | None) -> float:
    return time.time() if now is None else now


@dataclass(frozen=True)
class Pending:
    """What the browser's signed state cookie holds between the redirect and the callback."""

    state: str
    nonce: str
    verifier: str
    expires: int

    @classmethod
    def new(cls, now: float | None = None) -> "Pending":
        """Fresh random state, nonce and PKCE verifier."""
        return cls(
            state=secrets.token_urlsafe(24),
            nonce=secrets.token_urlsafe(24),
            verifier=secrets.token_urlsafe(48),
            expires=int(_now(now)) + STATE_TTL_SECONDS,
        )

    def seal(self, key: str) -> str:
        """The cookie value: the payload and its HMAC-SHA256 under the server's key."""
        body = _b64(json.dumps([self.state, self.nonce, self.verifier, self.expires]).encode())
        mac = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
        return f"{body}.{mac}"

    @classmethod
    def open(cls, value: str, key: str, now: float | None = None) -> "Pending":
        """The pending sign-in of a cookie value; ``SsoError('state')`` if forged or expired."""
        body, _, mac = value.partition(".")
        expected = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not body or not hmac.compare_digest(mac.encode(), expected.encode()):
            raise SsoError("state")
        try:
            state, nonce, verifier, expires = json.loads(_unb64(body))
            pending = cls(str(state), str(nonce), str(verifier), int(expires))
        except (ValueError, TypeError, binascii.Error) as error:
            raise SsoError("state") from error
        if pending.expires < _now(now):
            raise SsoError("state")
        return pending

    @property
    def challenge(self) -> str:
        """The PKCE S256 challenge of the verifier."""
        return _b64(hashlib.sha256(self.verifier.encode("ascii")).digest())


def redirect_uri(base: str) -> str:
    """The callback URL registered with Google for the server at ``base``."""
    return f"{base.rstrip('/')}{CALLBACK_PATH}"


def authorization_url(config: GoogleSso, pending: Pending, base: str) -> str:
    """Where the browser goes to choose a Google account."""
    query = {
        "client_id": config.client_id,
        "redirect_uri": redirect_uri(base),
        "response_type": "code",
        "scope": "openid email profile",
        "state": pending.state,
        "nonce": pending.nonce,
        "code_challenge": pending.challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    return f"{AUTH_URL}?{urlencode(query)}"


def exchange_code(config: GoogleSso, code: str, verifier: str, callback: str) -> Mapping[str, Any]:
    """Exchange the authorisation code at Google's token endpoint (10 s timeout)."""
    import httpx  # noqa: PLC0415 - loaded only when Google sign-in is used

    try:
        response = httpx.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "redirect_uri": callback,
                "code_verifier": verifier,
            },
            timeout=TOKEN_TIMEOUT_SECONDS,
        )
        body = response.json() if response.status_code == httpx.codes.OK else None
    except (httpx.HTTPError, ValueError) as error:
        raise SsoError("exchange") from error
    if not isinstance(body, dict):
        raise SsoError("exchange")
    return body


@dataclass(frozen=True)
class Identity:
    """The verified person of an ID token."""

    email: str
    name: str


def _claims(tokens: Mapping[str, Any]) -> dict[str, Any]:
    raw = tokens.get("id_token")
    if not isinstance(raw, str) or len(raw.split(".")) != JWT_PARTS:
        raise SsoError("token")
    try:
        claims = json.loads(_unb64(raw.split(".")[1]))
    except (ValueError, binascii.Error) as error:
        raise SsoError("token") from error
    if not isinstance(claims, dict):
        raise SsoError("token")
    return claims


def verify_id_token(
    config: GoogleSso, tokens: Mapping[str, Any], nonce: str, now: float | None = None
) -> Identity:
    """Check the ID token of a token response and return who signed in."""
    claims = _claims(tokens)
    expiry = claims.get("exp")
    fresh = isinstance(expiry, int | float) and expiry >= _now(now)
    nonce_ok = hmac.compare_digest(str(claims.get("nonce", "")).encode(), nonce.encode())
    if claims.get("iss") not in ISSUERS or claims.get("aud") != config.client_id:
        raise SsoError("token")
    if not fresh or not nonce_ok:
        raise SsoError("token")
    email = str(claims.get("email", "")).strip().lower()
    if claims.get("email_verified") not in {True, "true"} or "@" not in email:
        raise SsoError("unverified")
    if len(email) > MAX_USERNAME or not config.allows(email):
        raise SsoError("not_allowed")
    return Identity(email=email, name=str(claims.get("name", "")).strip()[:128])
