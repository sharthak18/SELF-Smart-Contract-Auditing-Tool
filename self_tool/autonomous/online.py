"""Opt-in network helpers for autonomous audits.

Imported only when the user passes ``self autonomous --online``.
Default ``self TARGET`` and ``self autonomous`` never import this module.

What it does (defensive metadata only, nothing is executed):

1. Fetch https:// links already present in the project's own docs.
2. Query OSV.dev for pinned dependency versions.

Safety: HTTPS only, DNS-resolved addresses must be public, size/time
caps, limited redirects, no private/link-local/metadata hosts.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from self_tool.autonomous.models import DependencyHit, ManifestFile
from self_tool.core.local_docs import extract_pdf_text, extract_urls, html_to_text
from self_tool.core.protocol_context import ProtocolContext


MAX_FETCHES = 8
MAX_BYTES = 400_000
TIMEOUT = 12.0
USER_AGENT = "SELF-Auditor/2.4 (opt-in doc+advisory fetch; never executes bodies)"

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_HOST = "api.osv.dev"

ECOSYSTEMS = {
    "npm": "npm",
    "npm-lock": "npm",
    "yarn-lock": "npm",
    "pnpm-lock": "npm",
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
    "cargo": "crates.io",
    "cargo-lock": "crates.io",
    "anchor": "crates.io",
}

SKIP_PACKAGES = {
    "version", "name", "license", "description", "main", "private",
    "type", "scripts", "dev", "test",
}


@dataclass
class FetchedRef:
    url: str
    kind: str
    ok: bool
    status: str
    text: str = ""
    chars: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "kind": self.kind,
            "ok": self.ok,
            "status": self.status,
            "chars": self.chars,
        }


@dataclass
class OnlineEnrichment:
    refs: List[FetchedRef] = field(default_factory=list)
    osv_hits: List[DependencyHit] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class OnlineError(RuntimeError):
    pass


def enrich_with_online(
    ctx: ProtocolContext,
    *,
    packages: Sequence[Tuple[str, str, str, str]] = (),
    fetch_docs: bool = True,
    fetch_advisories: bool = True,
    fetcher=None,
    osv_query=None,
) -> OnlineEnrichment:
    """Mutate ``ctx`` with fetched doc text and return OSV hits.

    ``fetcher`` / ``osv_query`` are injectable for tests.
    """
    result = OnlineEnrichment()
    do_fetch = fetcher or fetch_https_text
    if fetch_docs:
        for url in list(ctx.referenced_urls or [])[:MAX_FETCHES]:
            kind = "pdf" if url.lower().split("?", 1)[0].endswith(".pdf") else "doc"
            try:
                body, content_type = do_fetch(url)
                text = _body_to_text(body, content_type, url)
                ref = FetchedRef(url=url, kind=kind, ok=True, status="ok", text=text, chars=len(text))
            except Exception as exc:
                ref = FetchedRef(url=url, kind=kind, ok=False, status=f"{type(exc).__name__}: {exc}")
            result.refs.append(ref)
            ctx.fetched_refs.append(ref.to_dict())
            if ref.ok and ref.text:
                _merge_fetched_text(ctx, ref.url, ref.text)

    if fetch_advisories:
        query = osv_query or query_osv
        seen = set()
        queried = 0
        for name, version, ecosystem, source in packages:
            eco = ECOSYSTEMS.get(ecosystem)
            if not eco or not name or name.lower() in SKIP_PACKAGES:
                continue
            if not version or version in {"*", "unknown", "latest", "workspace:"}:
                continue
            key = (name.lower(), version, eco)
            if key in seen:
                continue
            seen.add(key)
            queried += 1
            if queried > 12:
                break
            try:
                vulns = query(name, version, eco)
            except Exception as exc:
                result.notes.append(f"OSV lookup failed for {name}@{version}: {type(exc).__name__}")
                continue
            for vuln in vulns:
                hit = _vuln_to_hit(vuln, name, version, eco, source)
                if hit:
                    result.osv_hits.append(hit)

    ok_refs = sum(1 for item in result.refs if item.ok)
    fail_refs = sum(1 for item in result.refs if not item.ok)
    if result.refs:
        result.notes.append(
            f"Online: fetched {ok_refs}/{len(result.refs)} inventoried link(s)"
            + (f", {fail_refs} failed" if fail_refs else "")
            + "."
        )
    if result.osv_hits:
        result.notes.append(f"Online: OSV returned {len(result.osv_hits)} advisory hit(s) for pinned dependencies.")
    elif fetch_advisories and queried:
        result.notes.append(f"Online: OSV queried {queried} pinned package(s); no matching advisories.")
    ctx.online_notes.extend(result.notes)
    return result


def fetch_https_text(url: str) -> Tuple[bytes, str]:
    """Fetch ``url`` over HTTPS with SSRF protections. Returns (body, content-type)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise OnlineError(f"non-HTTPS refused: {url}")
    if not parsed.hostname:
        raise OnlineError("missing host")
    _assert_public_host(parsed.hostname)
    if parsed.port not in {None, 443}:
        raise OnlineError(f"non-default port refused: {parsed.port}")

    context = ssl.create_default_context()
    if context.minimum_version is None or context.minimum_version < ssl.TLSVersion.TLSv1_2:
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    hops = 0
    current = url
    while hops <= 2:
        parsed = urlparse(current)
        if parsed.scheme != "https" or not parsed.hostname:
            raise OnlineError(f"redirect left HTTPS: {current}")
        _assert_public_host(parsed.hostname)
        request = urllib.request.Request(current, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html, text/plain, text/markdown, application/pdf, application/json, */*;q=0.1",
        })

        class _CaptureRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore
                raise _Redirect(newurl)

        opener = urllib.request.build_opener(
            _CaptureRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )
        try:
            with opener.open(request, timeout=TIMEOUT) as response:
                content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                body = bytearray()
                while len(body) < MAX_BYTES + 1:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise OnlineError(f"response exceeded {MAX_BYTES} bytes")
                return bytes(body), content_type
        except _Redirect as redirect:
            hops += 1
            current = str(redirect)
            continue
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, TimeoutError) as exc:
            raise OnlineError(f"fetch failed for {url}: {exc}") from exc
    raise OnlineError(f"too many redirects: {url}")


class _Redirect(Exception):
    pass


def _assert_public_host(hostname: str) -> None:
    host = (hostname or "").strip("[]").lower()
    if not host or host in {"localhost", "metadata.google.internal", "metadata"}:
        raise OnlineError(f"blocked host: {hostname}")
    if host.endswith(".local") or host.endswith(".internal"):
        raise OnlineError(f"blocked host: {hostname}")
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise OnlineError(f"DNS failed for {hostname}: {exc}") from exc
    if not infos:
        raise OnlineError(f"DNS empty for {hostname}")
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        ):
            raise OnlineError(f"non-public address for {hostname}: {ip}")


def _body_to_text(body: bytes, content_type: str, url: str) -> str:
    lowered = (content_type or "").lower()
    path = urlparse(url).path.lower()
    if "pdf" in lowered or path.endswith(".pdf"):
        return extract_pdf_text(body)
    text = body.decode("utf-8", errors="replace")
    if "html" in lowered or text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
        return html_to_text(text)
    if "json" in lowered:
        try:
            payload = json.loads(text)
            return json.dumps(payload, indent=2)[:20_000]
        except json.JSONDecodeError:
            return text[:20_000]
    return text[:20_000]


def _merge_fetched_text(ctx: ProtocolContext, url: str, text: str) -> None:
    """Fold fetched documentation into the contest-brief parser."""
    from self_tool.core.doc_reader import merge_brief_from_text

    heading = f"# Fetched from {url}\n\n{text}"
    merge_brief_from_text(ctx, heading)
    extra_urls = extract_urls(text, limit=8)
    for item in extra_urls:
        if item not in ctx.referenced_urls:
            ctx.referenced_urls.append(item)


def query_osv(name: str, version: str, ecosystem: str) -> List[dict]:
    payload = json.dumps({
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    _assert_public_host(OSV_HOST)
    context = ssl.create_default_context()
    if context.minimum_version is None or context.minimum_version < ssl.TLSVersion.TLSv1_2:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_BYTES)
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, TimeoutError) as exc:
        raise OnlineError(f"OSV query failed for {name}@{version}: {exc}") from exc
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise OnlineError("OSV returned non-JSON") from exc
    vulns = data.get("vulns") or []
    return [item for item in vulns if isinstance(item, dict)][:8]


def _vuln_to_hit(vuln: dict, name: str, version: str, ecosystem: str, source: str) -> Optional[DependencyHit]:
    ident = str(vuln.get("id") or "").strip()
    if not ident:
        return None
    severity = _osv_severity(vuln)
    if severity == "INFO":
        return None
    summary = (vuln.get("summary") or vuln.get("details") or ident).strip()
    if len(summary) > 400:
        summary = summary[:397] + "..."
    refs = []
    for item in vuln.get("references") or []:
        if isinstance(item, dict) and item.get("url"):
            refs.append(str(item["url"]))
        elif isinstance(item, str):
            refs.append(item)
    aliases = [str(a) for a in (vuln.get("aliases") or []) if a]
    return DependencyHit(
        id=f"AUTO-DEP-OSV-{ident}",
        package=name,
        version=version,
        ecosystem=ecosystem,
        severity=severity,
        title=summary.split("\n", 1)[0][:160] or ident,
        summary=summary,
        advisory_id=ident,
        source_file=source,
        references=(aliases + refs)[:8],
    )


def _osv_severity(vuln: dict) -> str:
    for item in vuln.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = str(item.get("score") or "")
        # CVSS vector often includes /AV:N; numeric scores appear as "9.8"
        match = None
        import re
        match = re.search(r"\b(\d+(?:\.\d+)?)\b", score)
        if match:
            value = float(match.group(1))
            if value >= 9.0:
                return "CRITICAL"
            if value >= 7.0:
                return "HIGH"
            if value >= 4.0:
                return "MEDIUM"
            if value > 0:
                return "LOW"
    specific = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(specific, str):
        upper = specific.upper()
        if upper in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return upper
        if "CRIT" in upper:
            return "CRITICAL"
        if "HIGH" in upper:
            return "HIGH"
        if "MED" in upper:
            return "MEDIUM"
        if "LOW" in upper:
            return "LOW"
    return "MEDIUM"


def collect_packages_from_manifests(manifests: Sequence[ManifestFile]) -> List[Tuple[str, str, str, str]]:
    from self_tool.autonomous.dependencies import _from_manifest

    found: List[Tuple[str, str, str, str]] = []
    for manifest in manifests:
        found.extend(_from_manifest(manifest))
    return found
