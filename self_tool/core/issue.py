"""
SELF — Smart Contract Exploit & Logic Finder
Core data model for a security finding/issue.
"""

from dataclasses import dataclass, field
from typing import List, Optional


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

    def __hash__(self):
        return hash((self.id, self.file, self.line))

    def __eq__(self, other):
        if not isinstance(other, Issue):
            return False
        return (self.id, self.file, self.line) == (other.id, other.file, other.line)
