"""Read-only, bounded and token-safe GitHub REST access for the G1 aggregate."""
from __future__ import annotations

from dataclasses import dataclass
from http.client import HTTPException
import re
import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from tools.g1_pr_aggregate_common import (
    AggregateError, MAX_ARCHIVE_BYTES, MAX_MEMBER_BYTES, _require, _strict_json,
)

MAX_JSON_RESPONSE_BYTES = MAX_MEMBER_BYTES
MAX_REDIRECTS = 5
MAX_URL_BYTES = 8192
READ_CHUNK_BYTES = 64 * 1024


def _reference(value: str) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= MAX_URL_BYTES,
             "GitHub URL is missing or exceeds its byte bound")
    _require(value.isascii() and all(32 < ord(char) < 127 for char in value),
             "GitHub URL contains unsupported characters")
    return value


def _https_url(value: str) -> str:
    _reference(value)
    try:
        parsed = urlparse(value)
        valid = (parsed.scheme == "https" and bool(parsed.hostname)
                 and parsed.username is None and parsed.password is None
                 and not parsed.fragment
                 and (parsed.port is None or 1 <= parsed.port <= 65535))
    except ValueError:
        valid = False
    _require(valid, "GitHub URL must be HTTPS without credentials, fragment or invalid port")
    return value


def _header(headers: Any, name: str) -> str | None:
    values = [value for key, value in headers.items() if key.lower() == name.lower()]
    _require(len(values) <= 1, f"duplicate HTTP {name} header")
    return values[0].strip() if values else None


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "GitHub response deadline exceeded")
    return remaining


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
    """Read-only HTTP with one response budget/deadline across redirect hops.

    Synchronous DNS/TLS/header/socket calls cannot be preempted by checkpoints;
    the caller's job deadline remains the outer execution bound. Artifact bytes
    remain in memory within the existing archive ceiling, not a measured RSS SLO.
    """

    def __init__(
        self,
        *,
        base_url: str = "https://api.github.com/",
        token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        _https_url(base_url)
        _require(not urlparse(base_url).query, "GitHub API base URL cannot have a query")
        _require(type(timeout) in (int, float) and 0.001 <= timeout <= 300,
                 "GitHub timeout must be finite within 0.001..300 seconds")
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.timeout = timeout
        self._no_redirect = build_opener(_NoRedirect())

    def _url(self, path_or_url: str) -> str:
        _reference(path_or_url)
        url = (path_or_url if path_or_url.startswith(("https://", "http://"))
               else urljoin(self.base_url, path_or_url.lstrip("/")))
        return _https_url(url)

    def _same_origin(self, url: str) -> bool:
        expected, actual = urlparse(self.base_url), urlparse(url)
        return (actual.scheme, actual.hostname, actual.port or 443) == (
            expected.scheme, expected.hostname, expected.port or 443,
        )

    @staticmethod
    def _read_body(response: Any, maximum: int, deadline: float) -> bytes:
        length_text = _header(response.headers, "Content-Length")
        transfer = _header(response.headers, "Transfer-Encoding")
        encoding = _header(response.headers, "Content-Encoding")
        _require(encoding is None or encoding.lower() == "identity",
                 "encoded HTTP response is not supported")
        _require(transfer is None or transfer.lower() == "chunked",
                 "unsupported HTTP transfer encoding")
        _require(not (transfer is not None and length_text is not None),
                 "ambiguous HTTP Content-Length and Transfer-Encoding")
        length = None
        if length_text is not None:
            _require(re.fullmatch(r"[0-9]{1,20}", length_text) is not None,
                     "invalid HTTP Content-Length")
            length = int(length_text)
            _require(length <= maximum, "HTTP response exceeds byte bound")
        raw = bytearray()
        # HTTPResponse.read1 exposes progress even on small trickled chunks.
        read = getattr(response, "read1", None) or response.read
        while True:
            _remaining(deadline)
            size = min(READ_CHUNK_BYTES, maximum - len(raw) + 1)
            chunk = read(size)
            _remaining(deadline)
            _require(isinstance(chunk, bytes) and len(chunk) <= size,
                     "invalid HTTP body read")
            if not chunk:
                break
            _require(len(raw) + len(chunk) <= maximum, "HTTP response exceeds byte bound")
            raw.extend(chunk)
        _require(length is None or len(raw) == length, "HTTP Content-Length mismatch")
        return bytes(raw)

    def _request(self, url: str, *, authenticated: bool, maximum: int,
                 same_origin_only: bool = False) -> ApiResponse:
        deadline = time.monotonic() + self.timeout
        seen: set[str] = set()
        for hop in range(MAX_REDIRECTS + 1):
            remaining = _remaining(deadline)
            _https_url(url)
            _require(not same_origin_only or self._same_origin(url),
                     "GitHub JSON response must remain on the API origin")
            _require(url not in seen, "GitHub redirect loop rejected")
            seen.add(url)
            headers = {
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "trillionnium-g1-pr-aggregate/1",
            }
            if authenticated and self._same_origin(url) and self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            request = Request(url, headers=headers, method="GET")
            try:
                with self._no_redirect.open(request, timeout=remaining) as response:
                    _remaining(deadline)
                    _require(response.getcode() == 200, "GitHub GET requires a complete HTTP 200 response")
                    _require(response.geturl() == url, "unexpected implicit HTTP redirect")
                    raw = self._read_body(response, maximum, deadline)
                    return ApiResponse(None, raw, url, dict(response.headers.items()))
            except HTTPError as error:
                try:
                    if error.code in {301, 302, 303, 307, 308}:
                        location = _header(error.headers, "Location")
                        _require(bool(location), "GitHub redirect Location is missing")
                        _require(hop < MAX_REDIRECTS, "GitHub redirect hop budget exceeded")
                        # Validate the raw reference before urljoin can remove controls.
                        url = _https_url(urljoin(url, _reference(location)))
                        # Even a later redirect back to the API cannot restore auth.
                        authenticated = False
                        continue
                    # Error bodies and signed URL query strings are not diagnostics.
                    raise AggregateError(f"GitHub GET failed HTTP {error.code}") from None
                finally:
                    error.close()
            except (URLError, OSError, HTTPException, ValueError) as error:
                raise AggregateError(f"GitHub GET transport failed ({type(error).__name__})") from None
        raise AggregateError("GitHub redirect hop budget exceeded")

    def get_json(self, path: str) -> ApiResponse:
        url = self._url(path)
        response = self._request(url, authenticated=self._same_origin(url),
                                 maximum=MAX_JSON_RESPONSE_BYTES, same_origin_only=True)
        return ApiResponse(_strict_json(response.raw, "GitHub JSON response"),
                           response.raw, response.url, response.headers)

    def get_bytes(self, path_or_url: str) -> ApiResponse:
        url = self._url(path_or_url)
        return self._request(url, authenticated=self._same_origin(url), maximum=MAX_ARCHIVE_BYTES)
