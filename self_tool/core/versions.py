"""Schema versions for SELF subsystems.

These are the single source of truth for compatibility between scans,
feedback records, advisory snapshots, and serialized project graphs.
Bump the relevant constant when the on-disk format changes in a way
that would invalidate older consumers.
"""

TOOL_SCHEMA_VERSION = 2
KNOWLEDGE_SCHEMA_VERSION = 2
FEEDBACK_SCHEMA_VERSION = 1
GRAPH_SCHEMA_VERSION = 1
INTELLIGENCE_SCHEMA_VERSION = 1
RULE_VERSION = "2.3.0"


def all_versions() -> dict:
    return {
        "tool": TOOL_SCHEMA_VERSION,
        "knowledge": KNOWLEDGE_SCHEMA_VERSION,
        "feedback": FEEDBACK_SCHEMA_VERSION,
        "graph": GRAPH_SCHEMA_VERSION,
        "intelligence": INTELLIGENCE_SCHEMA_VERSION,
        "rule": RULE_VERSION,
    }
