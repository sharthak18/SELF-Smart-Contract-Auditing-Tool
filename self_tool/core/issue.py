"""
SELF — Smart Contract Exploit & Logic Finder
Core data model for a security finding/issue.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class EvidenceLink:
    """One code location in a multi-hop project finding.

    The graph model reuses this dataclass so ``Issue`` remains the
    canonical report boundary. ``node_id`` is optional for ordinary
    per-file findings that do not participate in a project graph.
    """

    file: str
    start_line: int
    end_line: int
    text_hash: str
    relation: str = ""
    node_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "text_hash": self.text_hash,
            "relation": self.relation,
            "node_id": self.node_id,
        }


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

    @classmethod
    def emoji(cls, severity: str) -> str:
        return {
            cls.CRITICAL: "🔴",
            cls.HIGH:     "🟠",
            cls.MEDIUM:   "🟡",
            cls.LOW:      "🟢",
            cls.INFO:     "ℹ️",
        }.get(severity, "⚪")

    @classmethod
    def sort_key(cls, issue: "Issue") -> int:
        return cls.ORDER.get(issue.severity, 99)


class Confidence:
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class Issue:
    """Represents a single security finding."""
    id: str                          # e.g. "SOL-CRIT-001"
    title: str                       # Short title
    severity: str                    # Severity.CRITICAL etc.
    confidence: str                  # Confidence.HIGH etc.
    file: str                        # Relative file path
    line: int                        # Line number (1-indexed), 0 = file-level
    snippet: str                     # Relevant code snippet
    description: str                 # Full description of the vulnerability
    exploit_scenario: str            # How an attacker exploits it
    remediation: str                 # How to fix it
    references: List[str] = field(default_factory=list)  # Links, SWC IDs etc.
    language: str = "solidity"       # Language this detector targets

    # ── Context and deterministic review layer ─────────────────────────────
    suppressed: bool = False                 # Suppressed by explicit doc-context opt-in
    suppression_reason: str = ""            # Why suppressed
    context_note: str = ""                  # Untrusted documentation context

    review_status: Optional[str] = None
    review_reasoning: Optional[str] = None
    review_test: Optional[str] = None
    review_engine: Optional[str] = None

    # ── Fingerprint / suppression / evidence layer (additive) ──────────────
    project_fingerprint: str = ""           # Stable project fingerprint
    semantic_fingerprint: str = ""          # Finding identity without line numbers
    source_hash: str = ""                    # Hash of the code range that produced it
    rule_version: str = ""                   # Version of the detector that fired
    confidence_reasons: List[str] = field(default_factory=list)
    evidence_paths: List[EvidenceLink] = field(default_factory=list)
    suppression_state: str = "none"         # none | accepted_risk | false_positive

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the issue including fingerprint/evidence fields."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "language": self.language,
            "snippet": self.snippet,
            "description": self.description,
            "exploit_scenario": self.exploit_scenario,
            "remediation": self.remediation,
            "references": list(self.references),
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "suppression_state": self.suppression_state,
            "context_note": self.context_note,
            "review_status": self.review_status,
            "review_reasoning": self.review_reasoning,
            "review_test": self.review_test,
            "review_engine": self.review_engine,
            "project_fingerprint": self.project_fingerprint,
            "semantic_fingerprint": self.semantic_fingerprint,
            "source_hash": self.source_hash,
            "rule_version": self.rule_version,
            "confidence_reasons": list(self.confidence_reasons),
            "evidence_paths": [link.to_dict() for link in self.evidence_paths],
        }

    def __hash__(self):
        return hash((self.id, self.file, self.line))

    def __eq__(self, other):
        if not isinstance(other, Issue):
            return False
        return (self.id, self.file, self.line) == (other.id, other.file, other.line)
