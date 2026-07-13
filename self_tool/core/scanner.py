"""
SELF — Smart Contract Exploit & Logic Finder
Project scanner: discovers files, detects framework, dispatches to parsers.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# Files/dirs to always skip
SKIP_DIRS = {
    "node_modules", ".git", "out", "cache", "artifacts", "build",
    "lib", ".deps", "__pycache__", ".venv", "venv", "dist",
    "coverage", ".coverage", "typechain", "typechain-types",
    "test", "tests", "mock", "mocks",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", ".DS_Store",
}

# Language → file extensions
LANG_EXTENSIONS: Dict[str, List[str]] = {
    "solidity": [".sol"],
    "vyper": [".vy", ".vyi"],
    "huff": [".huff"],
    "rust": [".rs"],
    "move": [".move"],
    "typescript": [".ts", ".js"],
}

# Extension → language (reverse map)
EXT_TO_LANG: Dict[str, str] = {}
for lang, exts in LANG_EXTENSIONS.items():
    for ext in exts:
        EXT_TO_LANG[ext] = lang


class FileContext:
    """Parsed representation of a single source file."""

    def __init__(self, path: str, relative_path: str, language: str, content: str):
        self.path = path                    # Absolute path
        self.relative_path = relative_path  # Relative to project root
        self.language = language
        self.content = content
        self.lines = content.splitlines()
        self.line_count = len(self.lines)

    def get_snippet(self, line: int, context: int = 3) -> str:
        """Return a code snippet around a given line number (1-indexed)."""
        if line <= 0:
            return ""
        start = max(0, line - context - 1)
        end = min(len(self.lines), line + context)
        snippet_lines = []
        for i, src_line in enumerate(self.lines[start:end], start=start + 1):
            marker = "→ " if i == line else "  "
            snippet_lines.append(f"{marker}{i:4d} | {src_line}")
        return "\n".join(snippet_lines)

    def get_line(self, line: int) -> str:
        """Return content of a specific line (1-indexed)."""
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""


class FrameworkInfo:
    """Detected project framework metadata."""

    def __init__(self, name: str, root: str, src_dirs: List[str]):
        self.name = name        # "foundry", "hardhat", "anchor", "unknown"
        self.root = root        # Absolute path to project root
        self.src_dirs = src_dirs  # Source directories to scan


def detect_framework(root: str) -> FrameworkInfo:
    """Detect which framework a project uses."""
    root_path = Path(root)

    # Foundry
    if (root_path / "foundry.toml").exists() or (root_path / "forge.toml").exists():
        src_dirs = []
        # Try to read src from foundry.toml
        toml_path = root_path / "foundry.toml"
        if toml_path.exists():
            content = toml_path.read_text(errors="ignore")
            m = re.search(r'src\s*=\s*"([^"]+)"', content)
            if m:
                src_dirs = [str(root_path / m.group(1))]
        if not src_dirs:
            src_dirs = [str(root_path / "src"), str(root_path / "contracts")]
        return FrameworkInfo("foundry", root, src_dirs)

    # Hardhat
    if (root_path / "hardhat.config.js").exists() or (root_path / "hardhat.config.ts").exists():
        src_dirs = [str(root_path / "contracts"), str(root_path / "src")]
        return FrameworkInfo("hardhat", root, src_dirs)

    # Truffle
    if (root_path / "truffle-config.js").exists() or (root_path / "truffle.js").exists():
        src_dirs = [str(root_path / "contracts")]
        return FrameworkInfo("truffle", root, src_dirs)

    # Anchor (Solana/Rust)
    if (root_path / "Anchor.toml").exists():
        src_dirs = [str(root_path / "programs")]
        return FrameworkInfo("anchor", root, src_dirs)

    # Brownie
    if (root_path / "brownie-config.yaml").exists():
        src_dirs = [str(root_path / "contracts")]
        return FrameworkInfo("brownie", root, src_dirs)

    # Generic
    return FrameworkInfo("unknown", root, [root])


def discover_files(
    target: str,
    force_lang: Optional[str] = None,
) -> Tuple[List[FileContext], FrameworkInfo]:
    """
    Discover all smart contract files under `target`.
    Returns (list_of_file_contexts, framework_info).
    """
    target_path = Path(target).resolve()

    # If target is a single file
    if target_path.is_file():
        lang = force_lang or EXT_TO_LANG.get(target_path.suffix.lower())
        framework = detect_framework(str(target_path.parent))
        if not lang:
            return [], framework
        ctx = _load_file(target_path, target_path.parent, lang)
        return ([ctx] if ctx else [], framework)

    # If target is a directory
    framework = detect_framework(str(target_path))
    files = []

    for dirpath, dirnames, filenames in os.walk(str(target_path)):
        # Prune skip dirs in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]

        for filename in filenames:
            if filename in SKIP_FILES:
                continue

            filepath = Path(dirpath) / filename
            suffix = filepath.suffix.lower()

            if force_lang:
                if suffix not in LANG_EXTENSIONS.get(force_lang, []):
                    continue
                lang = force_lang
            else:
                lang = EXT_TO_LANG.get(suffix)
                if not lang:
                    continue

            ctx = _load_file(filepath, target_path, lang)
            if ctx:
                files.append(ctx)

    # Sort for deterministic output
    files.sort(key=lambda f: f.relative_path)
    return files, framework


def _load_file(filepath: Path, root: Path, language: str) -> Optional[FileContext]:
    """Load a source file. Empty files are ignored; read failures propagate."""
    content = filepath.read_text(encoding="utf-8", errors="replace")
    if not content.strip():
        return None
    relative = str(filepath.relative_to(root))
    return FileContext(
        path=str(filepath),
        relative_path=relative,
        language=language,
        content=content,
    )
