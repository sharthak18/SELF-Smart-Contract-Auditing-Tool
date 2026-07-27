"""Stable fingerprinting for projects, findings, and source contexts.

Fingerprints let the feedback store scope suppressions to exactly the
audit surface, detector revision, and code location that produced a
finding. They are deterministic, version-stable, and content-only —
they do not leak file paths.

The canonical JSON helper guarantees:

* key ordering is sorted
* unicode is preserved, escape-unique characters use ``ensure_ascii``
* no extra whitespace between tokens

That ordering is crucial: two equal fingerprints must produce the
same hash byte-for-byte across runs and Python versions.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


SUPPRESSION_STATES = ("none", "accepted_risk", "false_positive")
"""Allowed values for ``Issue.suppression_state``."""


def canonical_json(value: Any) -> str:
    """Serialize ``value`` deterministically."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if hasattr(value, "__dataclass_fields__") and not isinstance(value, type):
        return {key: getattr(value, key) for key in value.__dataclass_fields__}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def sha256_hex(payload: str | bytes) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def project_fingerprint(components: Mapping[str, Any]) -> str:
    """Compute a project fingerprint from a stable component mapping.

    Include the file set, the framework name, and the resolved
    import/inheritance summary — but never the absolute path.
    """
    return "pf_" + sha256_hex(canonical_json(dict(components)))[:32]


def source_context_hash(file: str, start_line: int, end_line: int, text: str) -> str:
    """Hash a code range so suppressions re-evaluate when the lines move.

    ``file`` here is the *relative* path, not the absolute path.
    """
    payload = {
        "file": file,
        "start": start_line,
        "end": end_line,
        "text": text,
    }
    return "sh_" + sha256_hex(canonical_json(payload))[:24]


def semantic_fingerprint(
    detector_id: str,
    rule_version: str,
    target_signature: Mapping[str, Any],
) -> str:
    """Hash a detector-finding identity independent of exact file/line.

    Use stable, semantic keys (``function_selector``, ``contract``,
    ``invariant``) so a renamed file with the same vulnerable site still
    suppresses correctly, while a real change re-surfaces the finding.
    """
    payload = {
        "detector": detector_id,
        "rule": rule_version,
        "target": dict(target_signature),
    }
    return "sf_" + sha256_hex(canonical_json(payload))[:24]
