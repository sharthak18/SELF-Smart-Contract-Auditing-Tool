"""Read an entire project: source, docs, manifests, lockfiles, extra languages."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple

from self_tool.autonomous.models import ManifestFile, ProjectIngestion
from self_tool.core.scanner import (
    EXT_TO_LANG,
    FileContext,
    SKIP_DIRS,
    discover_files,
)


EXTRA_LANG_EXTENSIONS = {
    "cairo": [".cairo"],
    "sway": [".sw"],
    "tact": [".tact"],
}

MANIFEST_NAMES = {
    "foundry.toml": "foundry",
    "forge.toml": "foundry",
    "remappings.txt": "remappings",
    "hardhat.config.js": "hardhat",
    "hardhat.config.ts": "hardhat",
    "truffle-config.js": "truffle",
    "package.json": "npm",
    "package-lock.json": "npm-lock",
    "yarn.lock": "yarn-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo-lock",
    "Anchor.toml": "anchor",
    "Move.toml": "move",
    "Sui.toml": "sui",
    "aptos.toml": "aptos",
    "Scarb.toml": "cairo",
    "Forc.toml": "sway",
    "brownie-config.yaml": "brownie",
    "vyper": "vyper-pin",
    "requirements.txt": "pip",
    "pyproject.toml": "python",
    "lib.rs": "rust-lib",
}

LOCK_KINDS = {"npm-lock", "yarn-lock", "pnpm-lock", "cargo-lock"}

DOC_NAMES = (
    "README.md", "README.rst", "README.txt", "README",
    "SECURITY.md", "ARCHITECTURE.md", "WHITEPAPER.md", "DESIGN.md",
)

MAX_MANIFEST_BYTES = 400_000
MAX_DOC_CHARS = 80_000
MAX_SOURCE_CHARS = 2_000_000


def extra_ext_to_lang() -> dict:
    mapping = {}
    for lang, exts in EXTRA_LANG_EXTENSIONS.items():
        for ext in exts:
            mapping[ext] = lang
    return mapping


def ingest_project(target: str, force_lang: Optional[str] = None) -> ProjectIngestion:
    target_path = Path(target).resolve()
    root = target_path if target_path.is_dir() else target_path.parent
    files, framework = discover_files(str(target_path), force_lang=force_lang)
    extra_source = _discover_extra_languages(root, target_path)
    manifests, lockfiles = _collect_manifests(root)
    docs_text = _collect_docs(root)
    combined_parts = [ctx.content for ctx in files]
    combined_parts.extend(ctx.content for ctx in extra_source)
    combined_parts.extend(item.content for item in manifests)
    combined_source = "\n".join(combined_parts)
    if len(combined_source) > MAX_SOURCE_CHARS:
        combined_source = combined_source[:MAX_SOURCE_CHARS]
    languages = sorted({ctx.language for ctx in list(files) + extra_source})
    return ProjectIngestion(
        root=str(root),
        framework=framework,
        files=files,
        extra_source=extra_source,
        manifests=manifests,
        lockfiles=lockfiles,
        docs_text=docs_text,
        combined_source=combined_source,
        languages=languages,
    )


def _discover_extra_languages(root: Path, target: Path) -> List[FileContext]:
    mapping = extra_ext_to_lang()
    found: List[FileContext] = []
    if target.is_file():
        lang = mapping.get(target.suffix.lower())
        if lang:
            ctx = _load(target, root, lang)
            return [ctx] if ctx else []
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")]
        for filename in filenames:
            path = Path(dirpath) / filename
            lang = mapping.get(path.suffix.lower())
            if not lang:
                continue
            ctx = _load(path, root, lang)
            if ctx:
                found.append(ctx)
    found.sort(key=lambda item: item.relative_path)
    return found


def _load(path: Path, root: Path, language: str) -> Optional[FileContext]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if not content.strip():
        return None
    try:
        relative = str(path.relative_to(root))
    except ValueError:
        relative = path.name
    return FileContext(str(path), relative, language, content)


def _collect_manifests(root: Path) -> Tuple[List[ManifestFile], List[ManifestFile]]:
    manifests: List[ManifestFile] = []
    lockfiles: List[ManifestFile] = []
    seen = set()
    candidates = []
    for name in MANIFEST_NAMES:
        candidates.append(root / name)
    # Also look one level down (monorepos / programs/).
    for child in sorted(root.iterdir()) if root.is_dir() else []:
        if not child.is_dir() or child.name in SKIP_DIRS or child.name.startswith("."):
            continue
        for name in MANIFEST_NAMES:
            candidates.append(child / name)
    for path in candidates:
        if not path.is_file():
            continue
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        kind = MANIFEST_NAMES.get(path.name, "manifest")
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if len(raw) > MAX_MANIFEST_BYTES:
            raw = raw[:MAX_MANIFEST_BYTES]
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        try:
            relative = str(path.relative_to(root))
        except ValueError:
            relative = path.name
        item = ManifestFile(relative_path=relative, kind=kind, content=text)
        if kind in LOCK_KINDS:
            lockfiles.append(item)
        manifests.append(item)
    return manifests, lockfiles


def _collect_docs(root: Path) -> str:
    chunks: List[str] = []
    for name in DOC_NAMES:
        path = root / name
        if path.is_file():
            chunks.append(_read_capped(path))
    for folder in ("docs", "documentation", "audits", "security"):
        directory = root / folder
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.md")):
            chunks.append(_read_capped(path))
            if sum(len(chunk) for chunk in chunks) > MAX_DOC_CHARS:
                break
    text = "\n\n".join(chunk for chunk in chunks if chunk)
    return text[:MAX_DOC_CHARS]


def _read_capped(path: Path, cap: int = 20_000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[:cap]


def all_file_contexts(ingestion: ProjectIngestion) -> List[FileContext]:
    return list(ingestion.files) + list(ingestion.extra_source)


def language_of_path(path: str) -> Optional[str]:
    suffix = Path(path).suffix.lower()
    return EXT_TO_LANG.get(suffix) or extra_ext_to_lang().get(suffix)
