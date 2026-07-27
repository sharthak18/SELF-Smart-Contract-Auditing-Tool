"""Strict validation for downloaded advisory records."""

from __future__ import annotations

import json
from typing import Any, Dict


MAX_FIELDS = 32
MAX_STRING_LEN = 1024
MAX_LIST_LEN = 200


def validate_record(payload: Any) -> Dict[str, Any]:
    """Validate a single advisory record.

    Returns the cleaned dict. Raises ``ValueError`` on any structural
    violation. Only the field allowlist below is accepted; everything
    else is dropped.
    """
    if not isinstance(payload, dict):
        raise ValueError("record must be a JSON object")
    if len(payload) > MAX_FIELDS:
        raise ValueError(f"record exceeds {MAX_FIELDS} fields")

    allowed = {"advisory_id", "source", "title", "summary", "severity",
               "affected_packages", "affected_versions", "cwes",
               "published_at", "references", "content_sha256",
               "retrieved_at", "source_revision"}
    cleaned: Dict[str, Any] = {}
    for key, value in payload.items():
        if key not in allowed:
            continue
        if isinstance(value, str):
            if len(value) > MAX_STRING_LEN:
                raise ValueError(f"field {key} exceeds {MAX_STRING_LEN} chars")
            cleaned[key] = value
        elif isinstance(value, list):
            if len(value) > MAX_LIST_LEN:
                raise ValueError(f"field {key} exceeds {MAX_LIST_LEN} entries")
            for entry in value:
                if not isinstance(entry, str) or len(entry) > MAX_STRING_LEN:
                    raise ValueError(f"list field {key} has invalid entry")
            cleaned[key] = value
        elif isinstance(value, (int, float, bool)):
            cleaned[key] = value
        elif value is None:
            continue
        else:
            raise ValueError(f"field {key} has unsupported type {type(value).__name__}")
    required = {"advisory_id", "source", "title", "content_sha256"}
    missing = sorted(required - set(cleaned))
    if missing:
        raise ValueError(f"record missing required fields: {missing}")
    return cleaned


def validate_record_list(payload: Any) -> Dict[str, Any]:
    """Validate a top-level container.

    Accepts either a JSON object with a top-level ``records`` list or a
    bare list of records.
    """
    if isinstance(payload, list):
        records = [validate_record(item) for item in payload]
        return {"records": records}
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        records = [validate_record(item) for item in payload["records"]]
        return {"records": records}
    raise ValueError("top-level container must be a list or object with 'records'")
