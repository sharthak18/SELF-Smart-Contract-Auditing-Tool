"""Local document inventory: links, PDFs, and prior-audit files.

Always offline. Network fetch lives in ``self_tool.autonomous.online``
and is imported only when the user passes ``--online``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


URL_RE = re.compile(
    r"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
)
SKIP_URL_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
    ".exe", ".wasm", ".bin", ".so", ".dylib",
)
SKIP_URL_HOST_BITS = (
    "localhost", "127.0.0.1", "0.0.0.0", "[::1]",
)
PRIOR_AUDIT_NAME_RE = re.compile(
    r"(audit|security.?review|spearbit|openzeppelin|trail.?of.?bits|"
    r"pashov|cantina|sherlock|code4rena|cyfrin|halborn|quantstamp|"
    r"certik|zellic|ackee|hexens|dedaub|fyeo|4naly3er|bot-report)",
    re.IGNORECASE,
)


def extract_urls(text: str, limit: int = 40) -> List[str]:
    """Return unique https:// URLs from markdown / HTML / plain text."""
    found: List[str] = []
    seen = set()
    for match in URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(").,;\"'>")
        if not _usable_url(url) or url in seen:
            continue
        seen.add(url)
        found.append(url)
        if len(found) >= limit:
            break
    return found


def _usable_url(url: str) -> bool:
    lower = url.lower()
    if any(bit in lower for bit in SKIP_URL_HOST_BITS):
        return False
    if any(lower.split("?", 1)[0].endswith(suffix) for suffix in SKIP_URL_SUFFIXES):
        return False
    if len(url) > 400:
        return False
    return True


def extract_pdf_text(data: bytes, cap: int = 20_000) -> str:
    """Best-effort text extraction from a PDF without extra dependencies.

    Reads literal strings from ``Tj`` / ``TJ`` operators and uncompressed
    text streams. Enough to acknowledge a prior-audit PDF; not a full
    layout engine.
    """
    if not data or not data.startswith(b"%PDF"):
        return ""
    try:
        raw = data.decode("latin-1", errors="replace")
    except Exception:
        return ""
    chunks: List[str] = []
    for match in re.finditer(r"\((?:\\.|[^\\)])*\)\s*Tj", raw):
        chunks.append(_pdf_literal(match.group(0).rsplit("Tj", 1)[0].strip()))
    for match in re.finditer(r"\[(.*?)\]\s*TJ", raw, re.DOTALL):
        for lit in re.finditer(r"\((?:\\.|[^\\)])*\)", match.group(1)):
            chunks.append(_pdf_literal(lit.group(0)))
    text = " ".join(item for item in chunks if item)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:cap]


def _pdf_literal(blob: str) -> str:
    if blob.startswith("(") and blob.endswith(")"):
        blob = blob[1:-1]
    blob = blob.replace(r"\n", "\n").replace(r"\r", "\n").replace(r"\t", " ")
    blob = blob.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
    blob = re.sub(r"\\([0-7]{1,3})", lambda m: chr(int(m.group(1), 8) % 256), blob)
    return blob.strip()


def html_to_text(html: str, cap: int = 20_000) -> str:
    text = html or ""
    text = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", text)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</(p|div|h[1-6]|li|tr)>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))) if int(m.group(1)) < 0x110000 else " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:cap]


def list_prior_audit_files(root: Path, extra: Sequence[Path] = ()) -> List[str]:
    """Relative paths of local audit reports (markdown + PDF)."""
    found: List[str] = []
    seen = set()
    roots = [root, *extra]
    folders = ("audits", "audit", "reports", "security", "docs")
    for base in roots:
        if not base.is_dir():
            continue
        for folder in folders:
            directory = base / folder
            if not directory.is_dir():
                continue
            for path in sorted(directory.rglob("*")):
                if not path.is_file():
                    continue
                suffix = path.suffix.lower()
                if suffix not in {".md", ".pdf", ".txt", ".html"}:
                    continue
                if not PRIOR_AUDIT_NAME_RE.search(path.name) and folder not in {"audits", "audit"}:
                    continue
                try:
                    rel = str(path.relative_to(root))
                except ValueError:
                    rel = str(path)
                if rel not in seen:
                    seen.add(rel)
                    found.append(rel)
    return found[:40]


def classify_url(url: str) -> str:
    lower = url.lower()
    if any(token in lower for token in ("audit", "spearbit", "openzeppelin.com/security", "cantina", "sherlock", "code4rena", "cyfrin", "halborn", "zellic")):
        return "prior-audit"
    if any(token in lower for token in ("docs.", "gitbook", "hackmd", "notion", "whitepaper", "documentation")):
        return "protocol-docs"
    if any(token in lower for token in ("nvd.nist", "osv.dev", "github.com/advisories", "cve.", "ghsa-")):
        return "advisory"
    if "github.com" in lower or "gitlab.com" in lower:
        return "source"
    return "link"


def summarize_refs(urls: Iterable[str], local_files: Iterable[str]) -> List[str]:
    notes = []
    local = list(local_files)
    if local:
        notes.append(f"Local prior-audit / security docs: {', '.join(local[:8])}.")
    kinds = {}
    for url in urls:
        kinds.setdefault(classify_url(url), []).append(url)
    if kinds.get("prior-audit"):
        notes.append(f"{len(kinds['prior-audit'])} linked prior-audit report(s) acknowledged (not treated as accepted risk).")
    if kinds.get("protocol-docs"):
        notes.append(f"{len(kinds['protocol-docs'])} protocol documentation link(s) inventoried.")
    leftover = sum(len(v) for k, v in kinds.items() if k not in {"prior-audit", "protocol-docs"})
    if leftover:
        notes.append(f"{leftover} other https link(s) inventoried from the project docs.")
    return notes
