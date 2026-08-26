"""Scan manifests and lockfiles for known vulnerable dependencies."""

from __future__ import annotations

import json
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from self_tool.autonomous.brain import load_dependency_advisories
from self_tool.autonomous.models import DependencyHit, ManifestFile, ProtocolUnderstanding


def scan_dependencies(
    manifests: Sequence[ManifestFile],
    understanding: Optional[ProtocolUnderstanding] = None,
) -> List[DependencyHit]:
    packages = _collect_packages(manifests, understanding)
    advisories = load_dependency_advisories()
    hits: List[DependencyHit] = []
    seen = set()
    for name, version, ecosystem, source in packages:
        for advisory in advisories:
            if not _name_matches(name, advisory):
                continue
            if advisory.get("ecosystem") not in {ecosystem, "foundry", "pypi"} and ecosystem not in {
                advisory.get("ecosystem"), "foundry", "unknown",
            }:
                # still allow foundry/npm aliasing for OZ
                if not _name_matches(name, advisory):
                    continue
            affected = advisory.get("affected") or "*"
            severity = (advisory.get("severity") or "MEDIUM").upper()
            # Wildcard INFO/LOW advisories (e.g. hardhat *) match every
            # package.json and drown first-party findings.
            if affected == "*" and severity in {"INFO", "LOW"}:
                continue
            if not version_in_range(version, affected):
                continue
            key = (advisory["id"], name, version, source)
            if key in seen:
                continue
            seen.add(key)
            hits.append(DependencyHit(
                id=f"AUTO-DEP-{advisory['id']}",
                package=name,
                version=version or "unknown",
                ecosystem=ecosystem,
                severity=advisory.get("severity") or "MEDIUM",
                title=advisory.get("title") or advisory["id"],
                summary=advisory.get("summary") or "",
                advisory_id=advisory["id"],
                source_file=source,
                references=list(advisory.get("references") or []),
            ))
    hits.sort(key=lambda item: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(item.severity, 9),
        item.package, item.advisory_id,
    ))
    return hits


def _collect_packages(
    manifests: Sequence[ManifestFile],
    understanding: Optional[ProtocolUnderstanding],
) -> List[Tuple[str, str, str, str]]:
    found: List[Tuple[str, str, str, str]] = []
    for manifest in manifests:
        found.extend(_from_manifest(manifest))
    if understanding:
        for match in re.finditer(r"#\s*@version\s+([\d.]+)", "\n".join(
            understanding.math_formulas
        )):
            found.append(("vyper", match.group(1), "pypi", "source"))
        # Also pull from contracts via architecture notes is weak; scan deps list.
        for dep in understanding.external_deps:
            if "@" in dep:
                name, version = dep.rsplit("@", 1)
                eco = "npm" if name.startswith("@") or "/" in name else "unknown"
                found.append((name, version.lstrip("^~=<>v"), eco, "import"))
    return found


def _from_manifest(manifest: ManifestFile) -> List[Tuple[str, str, str, str]]:
    out: List[Tuple[str, str, str, str]] = []
    text = manifest.content
    kind = manifest.kind
    path = manifest.relative_path
    if kind in {"npm", "npm-lock"}:
        out.extend(_from_package_json(text, path))
    if kind == "yarn-lock":
        for match in re.finditer(r'^"?(@?[^@\s"]+)@[^"]*"?:\s*\n\s*version\s+"([^"]+)"', text, re.MULTILINE):
            out.append((match.group(1), match.group(2), "npm", path))
    if kind == "cargo" or kind == "cargo-lock":
        out.extend(_from_toml_deps(text, path, "cargo"))
    if kind in {"foundry", "remappings"}:
        out.extend(_from_foundry(text, path))
    if kind in {"python", "pip"}:
        out.extend(_from_python(text, path))
    if kind == "move":
        out.extend(_from_toml_deps(text, path, "move"))
    if kind == "anchor":
        out.extend(_from_toml_deps(text, path, "cargo"))
    if kind == "vyper-pin":
        version = text.strip().splitlines()[0].strip() if text.strip() else ""
        if version:
            out.append(("vyper", version, "pypi", path))
    # Always look for vyper version pragma-like pins in any manifest.
    for match in re.finditer(r"vyper\s*[=:]\s*[\"']?([\d.]+)", text, re.IGNORECASE):
        out.append(("vyper", match.group(1), "pypi", path))
    return out


def _from_package_json(text: str, path: str) -> List[Tuple[str, str, str, str]]:
    out: List[Tuple[str, str, str, str]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            block = data.get(section) or {}
            if isinstance(block, dict):
                for name, version in block.items():
                    out.append((str(name), _clean_version(str(version)), "npm", path))
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, meta in packages.items():
                if not isinstance(meta, dict):
                    continue
                name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
                version = meta.get("version")
                if name and version:
                    out.append((str(name), str(version), "npm", path))
        return out
    for match in re.finditer(r'"(@?[A-Za-z0-9_./-]+)"\s*:\s*"([^"]+)"', text):
        name, version = match.group(1), match.group(2)
        if name in {"version", "name", "license", "description"}:
            continue
        out.append((name, _clean_version(version), "npm", path))
    return out


def _from_toml_deps(text: str, path: str, ecosystem: str) -> List[Tuple[str, str, str, str]]:
    out = []
    for match in re.finditer(
        r'^\s*([A-Za-z0-9_-]+)\s*=\s*(?:\{[^}]*version\s*=\s*["\']([^"\']+)|["\']([^"\']+)["\'])',
        text, re.MULTILINE,
    ):
        version = match.group(2) or match.group(3) or ""
        out.append((match.group(1), _clean_version(version), ecosystem, path))
    for match in re.finditer(r'tag\s*=\s*["\']v?([^"\']+)["\']', text):
        out.append(("openzeppelin-contracts", match.group(1), "foundry", path))
    return out


def _from_foundry(text: str, path: str) -> List[Tuple[str, str, str, str]]:
    out = []
    for match in re.finditer(r"@?openzeppelin[^\s=]*=[^\s]*", text, re.IGNORECASE):
        out.append(("openzeppelin-contracts", _guess_oz_version(text), "foundry", path))
    for match in re.finditer(r"solmate\s*=", text, re.IGNORECASE):
        out.append(("solmate", _version_near(text, "solmate"), "foundry", path))
    for match in re.finditer(r'tag\s*=\s*["\']v?([\d.]+)["\']', text):
        if "openzeppelin" in text.lower():
            out.append(("openzeppelin-contracts", match.group(1), "foundry", path))
    # Pinned solc version + via_ir flag: needed to flag the transient/persistent
    # storage clearing collision bug (solc 0.8.28-0.8.33 with --via-ir).
    solc_m = re.search(r'^\s*solc(?:_version)?\s*=\s*["\']v?([\d.]+)["\']', text, re.MULTILINE | re.IGNORECASE)
    via_ir_m = re.search(r'^\s*via_ir\s*=\s*true', text, re.MULTILINE | re.IGNORECASE)
    if solc_m and via_ir_m:
        out.append(("solc", solc_m.group(1), "foundry", path))
    return out


def _from_python(text: str, path: str) -> List[Tuple[str, str, str, str]]:
    out = []
    for match in re.finditer(r"^\s*([A-Za-z0-9_-]+)\s*(?:==|>=|~=)\s*([\d.]+)", text, re.MULTILINE):
        out.append((match.group(1), match.group(2), "pypi", path))
    return out


def _guess_oz_version(text: str) -> str:
    match = re.search(r"openzeppelin[^\"'\n]*[\"']v?([\d.]+)[\"']", text, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"tag\s*=\s*[\"']v?([\d.]+)[\"']", text)
    return match.group(1) if match else ""


def _version_near(text: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}[^\\n]{{0,80}}?([\d]+\.[\d.]+)", text, re.IGNORECASE)
    return match.group(1) if match else ""


def _clean_version(raw: str) -> str:
    raw = raw.strip().strip(",")
    raw = re.sub(r"^[~^>=<\s]*", "", raw)
    raw = raw.split(" ")[0].split(",")[0]
    return raw.lstrip("v")


def _name_matches(name: str, advisory: dict) -> bool:
    package = (advisory.get("package") or "").lower()
    aliases = [a.lower() for a in advisory.get("aliases") or []]
    cand = name.lower().rstrip("/")
    if cand == package or cand.endswith("/" + package) or package.endswith(cand):
        return True
    return cand in aliases or any(cand.endswith(alias) for alias in aliases)


def version_in_range(version: str, spec: str) -> bool:
    """Tiny semver-range matcher: ``*``, ``==X``, ``>=X,<Y`` combinations."""
    if not spec or spec == "*":
        return True
    if not version:
        # Unknown version: report only INFO/HIGH+ with wildcard-ish specs conservatively.
        return spec == "*"
    ver = _parse_version(version)
    if ver is None:
        return False
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        if clause.startswith(">="):
            other = _parse_version(clause[2:])
            if other is None or not (ver >= other):
                return False
        elif clause.startswith("<="):
            other = _parse_version(clause[2:])
            if other is None or not (ver <= other):
                return False
        elif clause.startswith(">"):
            other = _parse_version(clause[1:])
            if other is None or not (ver > other):
                return False
        elif clause.startswith("<"):
            other = _parse_version(clause[1:])
            if other is None or not (ver < other):
                return False
        elif clause.startswith("=="):
            other = _parse_version(clause[2:])
            if other != ver:
                return False
        else:
            other = _parse_version(clause)
            if other != ver:
                return False
    return True


def _parse_version(raw: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", raw.strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def hits_as_findings(hits: Sequence[DependencyHit], project_fingerprint: str) -> list:
    from self_tool.autonomous.models import AutonomousFinding
    from self_tool.core.fingerprints import semantic_fingerprint, source_context_hash
    from self_tool.core.versions import RULE_VERSION

    findings = []
    for hit in hits:
        if (hit.severity or "").upper() == "INFO":
            continue
        findings.append(AutonomousFinding(
            id=hit.id,
            title=f"Dependency: {hit.title}",
            severity=hit.severity,
            confidence="High" if hit.version not in {"", "unknown"} else "Medium",
            file=hit.source_file,
            line=1,
            language="dependency",
            snippet=f"{hit.package}@{hit.version} ({hit.ecosystem})",
            description=hit.summary,
            exploit_scenario=(
                "An attacker targets a known vulnerability in this pinned dependency "
                "rather than in first-party code."
            ),
            remediation=f"Upgrade {hit.package} off the affected range and re-run tests.",
            proof_obligation="Confirm the deployed bytecode or lockfile no longer resolves an affected version.",
            regression_recipe="Pin a fixed version and rerun `self autonomous`.",
            source="dependency",
            playbook_id=hit.advisory_id,
            references=list(hit.references),
            evidence=[f"{hit.package}@{hit.version}", hit.advisory_id],
            semantic_fingerprint=semantic_fingerprint(
                hit.advisory_id, RULE_VERSION,
                {"package": hit.package, "version": hit.version},
            ),
            source_hash=source_context_hash(hit.source_file, 1, 1, f"{hit.package}@{hit.version}"),
            project_fingerprint=project_fingerprint,
            rule_version=RULE_VERSION,
        ))
    return findings
