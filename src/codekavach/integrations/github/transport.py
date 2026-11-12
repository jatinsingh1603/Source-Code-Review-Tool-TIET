"""The one authenticated GitHub HTTP client (ADR-0003 exception: a named non-LLM transport).

Owning epic: E34.

This is the only module of the GitHub integration that imports a network client library. It
carries no finding text of its own: callers pass already-masked payloads. Features: bearer-token
auth, REST and GraphQL calls, Link-header pagination, primary rate limit handling (waits until
``x-ratelimit-reset`` when the remaining quota is zero), secondary limit handling
(``retry-after``), exponential backoff on 5xx and network errors, and a hard ceiling on the
total wait so a run never hangs. ``offline`` makes every call raise before a socket is opened.
The token is held in a private attribute and never logged or put in an error message.
"""

import time
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Final

import httpx

from codekavach.core.log import get_logger

_LOG = get_logger(__name__)
API_VERSION: Final = "2022-11-28"
DEFAULT_API_URL: Final = "https://api.github.com"
USER_AGENT: Final = "codekavach-github-integration"
MAX_WAIT_SECONDS: Final = 120.0


class GitHubError(Exception):
    """A GitHub call failed; ``status`` is the HTTP status or 0 for a transport failure."""

    def __init__(self, message: str, *, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class OfflineError(GitHubError):
    """The call was refused because the run is offline."""


class GitHubClient:
    """A small, rate-limit-aware client for the REST and GraphQL APIs."""

    def __init__(
        self,
        token: str | None,
        *,
        api_url: str = DEFAULT_API_URL,
        offline: bool = False,
        max_retries: int = 4,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token
        self._base = api_url.rstrip("/")
        self._offline = offline
        self._max_retries = max_retries
        self._sleep = sleep
        self._waited = 0.0
        self.requests_made = 0
        self._http = httpx.Client(
            timeout=timeout, transport=transport, follow_redirects=False, trust_env=False
        )

    def close(self) -> None:
        """Release the connection pool."""
        self._http.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def has_token(self) -> bool:
        """Whether a token is configured."""
        return bool(self._token)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _url(self, path: str) -> str:
        return path if path.startswith("https://") else f"{self._base}{path}"

    def _delay(self, response: httpx.Response, attempt: int) -> float | None:
        """Seconds to wait before a retry, or ``None`` when the response is final."""
        status = response.status_code
        retry_after = response.headers.get("retry-after")
        remaining = response.headers.get("x-ratelimit-remaining")
        if status in (403, 429) and (retry_after or remaining == "0"):
            if retry_after and retry_after.isdigit():
                return float(retry_after) + 1.0
            reset = response.headers.get("x-ratelimit-reset")
            if reset and reset.isdigit():
                return max(1.0, float(reset) - time.time() + 1.0)
            return 60.0
        if status in (500, 502, 503, 504):
            return min(2.0**attempt, 30.0)
        return None

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        ok: tuple[int, ...] = (),
    ) -> httpx.Response:
        """One call with retries; raises ``GitHubError`` unless the status is 2xx or in ``ok``."""
        if self._offline:
            raise OfflineError("offline: GitHub was not contacted")
        attempt = 0
        while True:
            self.requests_made += 1
            try:
                response = self._http.request(
                    method, self._url(path), json=json, params=params, headers=self._headers()
                )
            except httpx.TransportError as error:
                if attempt >= self._max_retries:
                    raise GitHubError(f"network error: {type(error).__name__}") from None
                delay: float | None = min(2.0**attempt, 30.0)
            else:
                delay = self._delay(response, attempt)
                if delay is None or attempt >= self._max_retries:
                    return self._checked(response, method, path, ok)
            attempt += 1
            if delay is None or self._waited + delay > MAX_WAIT_SECONDS:
                raise GitHubError("rate limit or server error persisted; giving up")
            _LOG.warning("github.backoff", extra={"delay": delay, "attempt": attempt})
            self._waited += delay
            self._sleep(delay)

    @staticmethod
    def _checked(
        response: httpx.Response, method: str, path: str, ok: tuple[int, ...]
    ) -> httpx.Response:
        if response.is_success or response.status_code in ok:
            return response
        message = _error_message(response)
        raise GitHubError(f"GitHub {method} {path} failed: {message}", status=response.status_code)

    def get_json(self, path: str, **params: Any) -> Any:
        """GET and decode JSON."""
        return self.request("GET", path, params=params or None).json()

    def paginate(self, path: str, **params: Any) -> Iterator[Any]:
        """Yield every item of a list endpoint, following ``Link: rel=next``."""
        url: str | None = path
        query: dict[str, Any] | None = {"per_page": 100, **params}
        while url:
            response = self.request("GET", url, params=query)
            data = response.json()
            yield from data if isinstance(data, list) else data.get("items", [])
            url = response.links.get("next", {}).get("url")
            query = None

    def graphql(self, query: str, variables: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Run a GraphQL query; raises on transport or GraphQL errors."""
        response = self.request(
            "POST", "/graphql", json={"query": query, "variables": dict(variables or {})}
        )
        body = response.json()
        if body.get("errors"):
            first = body["errors"][0].get("message", "unknown error")
            raise GitHubError(f"GitHub GraphQL error: {first}", status=response.status_code)
        data: dict[str, Any] = body.get("data") or {}
        return data


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    if isinstance(body, dict) and body.get("message"):
        return f"HTTP {response.status_code}: {str(body['message'])[:200]}"
    return f"HTTP {response.status_code}"
