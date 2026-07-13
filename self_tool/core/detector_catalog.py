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
            detector_id = _text(keywords.get("id"))
            if not detector_id:
                continue
            title = _text(keywords.get("title")) or detector_id.replace("-", " ").title()
            rules[detector_id] = DetectorMetadata(
                id=detector_id,
                language=language,
                severity=_severity(detector_id, keywords.get("severity")),
                title=title,
                module=module,
                line=node.lineno,
            )

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(
        rules.values(),
        key=lambda rule: (
            severity_order.get(rule.severity, 99),
            rule.language,
            rule.id,
        ),
    )
