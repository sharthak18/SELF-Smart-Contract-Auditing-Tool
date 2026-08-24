"""Autonomous AI audit layer.

This package is **not** imported by the default ``self TARGET`` scan
path. It is loaded only when the user invokes ``self autonomous`` or
``self train``. That keeps the offline-by-default detector engine
untouched.
"""

from self_tool.autonomous.models import AutonomousAudit, AutonomousFinding
from self_tool.autonomous.pipeline import run_autonomous_audit

__all__ = ["AutonomousAudit", "AutonomousFinding", "run_autonomous_audit"]
