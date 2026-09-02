"""Read-only, token-safe GitHub REST access for the G1 aggregate."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from tools.g1_pr_aggregate_common import AggregateError, _require, _strict_json

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class ApiResponse:
    value: Any
    raw: bytes
    url: str
    headers: Mapping[str, str]


class GitHubApi:
    """Read-only GitHub REST client that never forwards a token to redirects."""

    def __init__(
        self,
        *,
        base_url: str = "https://api.github.com/",
        token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.timeout = timeout
        self._no_redirect = build_opener(_NoRedirect())

    def _url(self, path_or_url: str) -> str:
        url = (
            path_or_url
            if path_or_url.startswith(("https://", "http://"))
            else urljoin(self.base_url, path_or_url.lstrip("/"))
        )
        parsed = urlparse(url)
        _require(parsed.scheme == "https" and bool(parsed.netloc), f"GitHub URL must be absolute HTTPS: {url}")
        return url

    def _same_origin(self, url: str) -> bool:
        expected = urlparse(self.base_url)
        actual = urlparse(url)
        return (actual.scheme, actual.hostname, actual.port or 443) == (
            expected.scheme,
            expected.hostname,
            expected.port or 443,
        )

    def _request(self, url: str, *, authenticated: bool) -> ApiResponse:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trillionnium-g1-pr-aggregate/1",
        }
        if authenticated and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(url, headers=headers, method="GET")
        try:
            with self._no_redirect.open(request, timeout=self.timeout) as response:
                raw = response.read()
                return ApiResponse(None, raw, response.geturl(), dict(response.headers.items()))
        except HTTPError as error:
            if error.code in {301, 302, 303, 307, 308} and error.headers.get("Location"):
                location = urljoin(url, error.headers["Location"])
                parsed = urlparse(location)
                _require(parsed.scheme == "https" and bool(parsed.netloc), "artifact redirect must remain HTTPS")
                return self._request(location, authenticated=False)
            detail = error.read().decode("utf-8", errors="replace")[:400]
            raise AggregateError(f"GitHub GET {url} failed HTTP {error.code}: {detail}") from error
        except (URLError, OSError) as error:
            raise AggregateError(f"GitHub GET {url} failed: {error}") from error

    def get_json(self, path: str) -> ApiResponse:
        url = self._url(path)
        response = self._request(url, authenticated=self._same_origin(url))
        return ApiResponse(_strict_json(response.raw, url), response.raw, response.url, response.headers)

    def get_bytes(self, path_or_url: str) -> ApiResponse:
        url = self._url(path_or_url)
        return self._request(url, authenticated=self._same_origin(url))


