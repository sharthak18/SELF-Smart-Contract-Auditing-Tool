"""Metadata-only registration for project detectors.

Each ``Issue(...)`` literal here is consumed by the catalog scanner
(``self_tool.core.detector_catalog``) so that project detector IDs are
visible to the review-profile parity check. The actual findings are
emitted via :func:`self_tool.detectors.project.project_base.make_issue`
and the per-detector modules under this package.

The :class:`Issue` objects constructed below are immediately discarded;
they exist only to provide AST-visible metadata. The runtime never
inspects them.
"""

from self_tool.core.issue import Confidence, Issue, Severity


# PROJECT-ACCESS-001
Issue(
    id="PROJECT-ACCESS-001",
    title="Cross-contract access control mismatch",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    file="",
    line=0,
    snippet="",
    description="",
    exploit_scenario="",
    remediation="",
)

# PROJECT-PROXY-001
Issue(
    id="PROJECT-PROXY-001",
    title="Proxy / delegatecall hazard across the project graph",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    file="",
    line=0,
    snippet="",
    description="",
    exploit_scenario="",
    remediation="",
)

# PROJECT-REENTRANCY-001
Issue(
    id="PROJECT-REENTRANCY-001",
    title="Multi-contract reentrancy path",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    file="",
    line=0,
    snippet="",
    description="",
    exploit_scenario="",
    remediation="",
)

# PROJECT-AUTH-001
Issue(
    id="PROJECT-AUTH-001",
    title="Authorization-to-state-write coverage",
    severity=Severity.MEDIUM,
    confidence=Confidence.LOW,
    file="",
    line=0,
    snippet="",
    description="",
    exploit_scenario="",
    remediation="",
)

# PROJECT-ORACLE-001
Issue(
    id="PROJECT-ORACLE-001",
    title="Oracle / dependency trust-boundary mapping",
    severity=Severity.MEDIUM,
    confidence=Confidence.LOW,
    file="",
    line=0,
    snippet="",
    description="",
    exploit_scenario="",
    remediation="",
)

# PROJECT-UNRESOLVED-001
Issue(
    id="PROJECT-UNRESOLVED-001",
    title="Unresolved graph edge disclosure",
    severity=Severity.INFO,
    confidence=Confidence.HIGH,
    file="",
    line=0,
    snippet="",
    description="",
    exploit_scenario="",
    remediation="",
)
