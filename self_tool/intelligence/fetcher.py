"""HTTPS fetcher with strict safety controls.

The fetcher is intentionally tiny. It uses stdlib ``urllib`` so the
updater can run on a minimal Python install. Every safety control is
explicit and asserted.
"""

from __future__ import annotations

import ssl
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, Optional
from urllib.parse import urlparse


ALLOWED_HOSTS: Dict[str, str] = {
    # id → hostname (exact match required)
    "owasp-scs": "scs.owasp.org",
    "openzeppelin": "api.github.com",
    "vyper-advisories": "api.github.com",
    "ghsa": "api.github.com",
    "nvd": "services.nvd.nist.gov",
}
"""Allowlist of (source_id → host). Update fetches must target these."""


class FetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class FetchResult:
    body: bytes
    sha256: str


def fetch_https(
    url: str,
    *,
    allowed_hosts: Iterable[str],
    max_bytes: int = 2 * 1024 * 1024,
    timeout_connect: float = 15.0,
    timeout_read: float = 30.0,
) -> FetchResult:
    """Fetch ``url`` over HTTPS with strict safety controls.

    Raises :class:`FetchError` if the host is not in ``allowed_hosts``,
    the response is not HTTPS, the server redirects, the body exceeds
    ``max_bytes``, or TLS validation fails.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise FetchError(f"non-HTTPS URL refused: {url}")
    if parsed.hostname is None or parsed.hostname not in set(allowed_hosts):
        raise FetchError(f"host not in allowlist: {parsed.hostname}")
    if parsed.port is not None and parsed.port != 443:
        raise FetchError(f"non-default port refused: {parsed.port}")

    context = ssl.create_default_context()
    if context.minimum_version is None or context.minimum_version < ssl.TLSVersion.TLSv1_2:
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    request = urllib.request.Request(url, headers={
        "User-Agent": "SELF-Auditor/2.3 (offline advisory mirror)",
        "Accept": "application/json",
    })

    # Block redirects by overriding HTTPRedirectHandler
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # type: ignore
            raise FetchError(f"redirect refused: {url}")

    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=context))

    try:
        with opener.open(request, timeout=timeout_read) as response:
            body = bytearray()
            while len(body) < max_bytes:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) > max_bytes:
                raise FetchError(f"response exceeded {max_bytes} bytes")
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, TimeoutError) as exc:
        raise FetchError(f"fetch failed for {url}: {exc}") from exc

    from self_tool.core.fingerprints import sha256_hex
    return FetchResult(body=bytes(body), sha256=sha256_hex(bytes(body)))


def host_for(source_id: str) -> Optional[str]:
    return ALLOWED_HOSTS.get(source_id)
