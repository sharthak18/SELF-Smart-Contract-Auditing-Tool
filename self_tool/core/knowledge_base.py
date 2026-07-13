"""Load and validate SELF's defensive security knowledge metadata."""

import json
from pathlib import Path
from typing import Any, Dict, List

from self_tool.core.detector_catalog import DetectorMetadata


KNOWLEDGE_PATH = Path(__file__).parent.parent / "knowledge" / "security_knowledge.json"


def load_security_knowledge() -> Dict[str, Any]:
    with KNOWLEDGE_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)
    validate_security_knowledge(data)
    return data


def validate_security_knowledge(data: Dict[str, Any]) -> None:
    if data.get("schema_version") != 1:
        raise ValueError("unsupported security knowledge schema")

    source_ids = [source.get("id") for source in data.get("sources", [])]
    if not source_ids or len(source_ids) != len(set(source_ids)):
        raise ValueError("knowledge sources must have unique IDs")

    category_ids: List[str] = []
    for taxonomy in data.get("taxonomies", []):
        for category in taxonomy.get("categories", []):
            category_ids.append(category.get("id"))
            if not category.get("detector_ids"):
                raise ValueError(f"knowledge category {category.get('id')} has no detector mappings")
    if not category_ids or len(category_ids) != len(set(category_ids)):
        raise ValueError("knowledge categories must have unique IDs")


def knowledge_coverage(
    data: Dict[str, Any],
    detectors: List[DetectorMetadata],
) -> List[Dict[str, Any]]:
    known_ids = {detector.id for detector in detectors}
    coverage = []
    for taxonomy in data.get("taxonomies", []):
        for category in taxonomy.get("categories", []):
            mapped = category["detector_ids"]
            coverage.append({
                "taxonomy": taxonomy["name"],
                "id": category["id"],
                "name": category["name"],
                "mapped": len([detector_id for detector_id in mapped if detector_id in known_ids]),
                "missing": sorted(set(mapped) - known_ids),
            })
    return coverage
