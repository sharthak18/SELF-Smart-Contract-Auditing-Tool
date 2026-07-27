"""Discover detector rule metadata without executing detector code."""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class DetectorMetadata:
    id: str
    language: str
    severity: str
    title: str
    module: str
    line: int


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _keywords(node: ast.Call) -> Dict[str, ast.AST]:
    return {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}


def _text(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                try:
                    parts.append("{" + ast.unparse(value.value) + "}")
                except Exception:
                    parts.append("{value}")
        return "".join(parts)
    return None


def _text_literals(node: Optional[ast.AST]) -> List[str]:
    """Walk an expression and collect every string literal it contains.

    Handles conditional IDs like ``id="X" if cond else "Y"`` by registering
    both possible IDs so review profiles can be matched regardless of which
    branch the runtime emits.
    """
    found: List[str] = []
    if node is None:
        return found
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.append(child.value)
    return found


def _severity(detector_id: str, node: Optional[ast.AST]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.upper()
    if isinstance(node, ast.Attribute):
        return node.attr.upper()

    id_parts = detector_id.split("-")
    aliases = {"CRIT": "CRITICAL", "MED": "MEDIUM"}
    for part in id_parts:
        severity = aliases.get(part, part)
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            return severity
    return "UNKNOWN"


def load_detector_catalog(detectors_root: Optional[Path] = None) -> List[DetectorMetadata]:
    root = detectors_root or Path(__file__).parent.parent / "detectors"
    rules: Dict[str, DetectorMetadata] = {}

    for path in sorted(root.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue

        language = path.parent.name
        module = ".".join(path.relative_to(root.parent).with_suffix("").parts)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) not in {"Issue", "as_issues"}:
                continue
            keywords = _keywords(node)
            id_node = keywords.get("id")
            # Collect every literal id candidate — supports ternary
            # ``id="X" if cond else "Y"`` so review profiles for both
            # branches are reachable.
            candidates = _text_literals(id_node) or (
                [_text(id_node)] if _text(id_node) else []
            )
            if not candidates:
                continue
            title = _text(keywords.get("title")) or candidates[0].replace("-", " ").title()
            severity = _severity(candidates[0], keywords.get("severity"))
            for detector_id in candidates:
                rules[detector_id] = DetectorMetadata(
                    id=detector_id,
                    language=language,
                    severity=severity,
                    title=title,
                    module=module,
                    line=node.lineno,
                )

    # ── Merge exploit-corpus rules (rules derived from real incidents) ───────
    try:
        from self_tool.knowledge.exploit_corpus import load_exploit_corpus
        for exp in load_exploit_corpus().values():
            rules[exp.detector_id] = DetectorMetadata(
                id=exp.detector_id,
                language="solidity",
                severity=exp.severity,
                title=exp.title,
                module="self_tool.knowledge.exploit_corpus",
                line=0,
            )
    except Exception:
        # Corpus missing — fall back to detector-only catalog
        pass

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(
        rules.values(),
        key=lambda rule: (
            severity_order.get(rule.severity, 99),
            rule.language,
            rule.id,
        ),
    )
