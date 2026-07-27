"""Local persistent feedback store for SELF.

The feedback package stores confirmations, false positives, accepted
risks, and fix annotations in a SQLite database located at
``~/.self-auditor/feedback.sqlite3`` by default. Suppression is
explicit, fingerprint-scoped, and reversible.

Public API:
    * :func:`FeedbackStore.add / list / remove / export / import`
    * :func:`apply_suppressions(issues, project_fingerprint)`
"""

from .schema import (
    DISPOSITIONS,
    FEEDBACK_SCHEMA_VERSION,
    FeedbackEntry,
    schema_version,
)
from .service import FeedbackStore, apply_suppressions

__all__ = [
    "DISPOSITIONS",
    "FEEDBACK_SCHEMA_VERSION",
    "FeedbackEntry",
    "FeedbackStore",
    "apply_suppressions",
    "schema_version",
]
