"""Data models for the autonomous audit layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from self_tool.core.issue import Issue


@dataclass
class ManifestFile:
    """A non-source project file the auditor read for context."""

    relative_path: str
    kind: str
    content: str


@dataclass
class ExtractedFunction:
    """Language-agnostic function surface used by the reasoner."""

    language: str
    file: str
    contract: str
    name: str
    line: int
    visibility: str
    mutability: str
    modifiers: List[str]
    params: str
    body: str
    state_writes: List[str] = field(default_factory=list)
    external_calls: List[str] = field(default_factory=list)
    is_privileged_name: bool = False


@dataclass
class ExtractedContract:
    """Language-agnostic contract / program / module."""

    language: str
    file: str
    name: str
    kind: str
    line: int
    inherits: List[str] = field(default_factory=list)
    functions: List[ExtractedFunction] = field(default_factory=list)
    state_vars: List[str] = field(default_factory=list)
    role_guess: str = "unknown"


@dataclass
class TokenFlow:
    direction: str
    function: str
    file: str
    line: int
    detail: str


@dataclass
class ProtocolUnderstanding:
    name: str
    types: List[str]
    summary: str
    languages: List[str]
    contracts: List[ExtractedContract]
    facts: Dict[str, bool]
    token_flows: List[TokenFlow]
    invariants: List[str]
    math_formulas: List[str]
    privileged_ops: List[str]
    permissionless_ops: List[str]
    external_deps: List[str]
    architecture_notes: List[str]
    source_chars: int
    file_count: int
    known_issues: List[str] = field(default_factory=list)
    out_of_scope_paths: List[str] = field(default_factory=list)
    in_scope_paths: List[str] = field(default_factory=list)
    trusted_roles: List[str] = field(default_factory=list)
    accepted_playbooks: List[str] = field(default_factory=list)
    referenced_urls: List[str] = field(default_factory=list)
    local_audit_files: List[str] = field(default_factory=list)
    fetched_refs: List[Dict[str, Any]] = field(default_factory=list)
    # Must-hold properties SELF could not confirm, rendered as Foundry sketches.
    hypotheses: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "types": list(self.types),
            "summary": self.summary,
            "languages": list(self.languages),
            "facts": dict(self.facts),
            "invariants": list(self.invariants),
            "math_formulas": list(self.math_formulas),
            "privileged_ops": list(self.privileged_ops),
            "permissionless_ops": list(self.permissionless_ops),
            "external_deps": list(self.external_deps),
            "architecture_notes": list(self.architecture_notes),
            "source_chars": self.source_chars,
            "file_count": self.file_count,
            "known_issues": list(self.known_issues),
            "out_of_scope_paths": list(self.out_of_scope_paths),
            "in_scope_paths": list(self.in_scope_paths),
            "trusted_roles": list(self.trusted_roles),
            "accepted_playbooks": list(self.accepted_playbooks),
            "referenced_urls": list(self.referenced_urls),
            "local_audit_files": list(self.local_audit_files),
            "fetched_refs": list(self.fetched_refs),
            "hypotheses": list(self.hypotheses),
            "contracts": [
                {
                    "language": c.language,
                    "file": c.file,
                    "name": c.name,
                    "kind": c.kind,
                    "role_guess": c.role_guess,
                    "inherits": list(c.inherits),
                    "state_vars": list(c.state_vars),
                    "function_count": len(c.functions),
                }
                for c in self.contracts
            ],
            "token_flows": [
                {
                    "direction": f.direction,
                    "function": f.function,
                    "file": f.file,
                    "line": f.line,
                    "detail": f.detail,
                }
                for f in self.token_flows
            ],
        }

    def briefing(self, limit: int = 4000) -> str:
        """Compact, deterministic text used for retrieval and optional LLM."""
        lines = [
            f"Protocol: {self.name}",
            f"Types: {', '.join(self.types) or 'unknown'}",
            f"Languages: {', '.join(self.languages) or 'unknown'}",
            f"Summary: {self.summary}",
            "Facts: " + ", ".join(
                key for key, value in sorted(self.facts.items()) if value
            ),
            "Contracts:",
        ]
        for contract in self.contracts:
            lines.append(
                f"- {contract.language} {contract.role_guess} {contract.name} "
                f"in {contract.file} inherits={','.join(contract.inherits) or '-'}"
            )
        if self.privileged_ops:
            lines.append("Privileged: " + "; ".join(self.privileged_ops[:20]))
        if self.permissionless_ops:
            lines.append("Permissionless: " + "; ".join(self.permissionless_ops[:20]))
        if self.math_formulas:
            lines.append("Math: " + "; ".join(self.math_formulas[:12]))
        if self.invariants:
            lines.append("Guards: " + "; ".join(self.invariants[:16]))
        if self.hypotheses:
            lines.append(
                "Must-hold invariants (hypotheses, not proofs): "
                + "; ".join(self.hypotheses[:12])
            )
        if self.external_deps:
            lines.append("Deps: " + ", ".join(self.external_deps[:20]))
        if self.trusted_roles:
            lines.append("Trusted roles: " + ", ".join(self.trusted_roles[:16]))
        if self.known_issues:
            lines.append("Known issues: " + " | ".join(self.known_issues[:8]))
        if self.accepted_playbooks:
            lines.append("Accepted playbooks: " + ", ".join(self.accepted_playbooks))
        if self.out_of_scope_paths:
            lines.append(f"Out of scope files: {len(self.out_of_scope_paths)}")
        if self.local_audit_files:
            lines.append("Local audit docs: " + ", ".join(self.local_audit_files[:8]))
        if self.referenced_urls:
            lines.append(f"Documented links: {len(self.referenced_urls)}")
        fetched_ok = [item for item in self.fetched_refs if item.get("ok")]
        if fetched_ok:
            lines.append(f"Fetched references: {len(fetched_ok)}")
        text = "\n".join(lines)
        return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass
class Playbook:
    id: str
    title: str
    severity: str
    languages: List[str]
    protocol_types: List[str]
    owasp: str
    cwe: List[str]
    swc: List[str]
    required_any_patterns: List[str]
    required_all_patterns: List[str]
    forbidden_patterns: List[str]
    fact_predicates: List[str]
    related_detectors: List[str]
    description: str
    exploit: str
    remediation: str
    proof_obligation: str
    real_incidents: List[str]
    weight: float = 1.0

    def search_text(self) -> str:
        parts = [
            self.id, self.title, self.description, self.exploit,
            self.remediation, " ".join(self.real_incidents),
            " ".join(self.protocol_types), " ".join(self.languages),
            " ".join(self.fact_predicates),
        ]
        return " ".join(parts)


@dataclass
class RetrievedDoc:
    doc_id: str
    kind: str
    title: str
    score: float
    snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "kind": self.kind,
            "title": self.title,
            "score": self.score,
            "snippet": self.snippet,
        }


@dataclass
class AutonomousFinding:
    id: str
    title: str
    severity: str
    confidence: str
    file: str
    line: int
    language: str
    snippet: str
    description: str
    exploit_scenario: str
    remediation: str
    proof_obligation: str
    regression_recipe: str
    source: str
    playbook_id: str = ""
    references: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    related_detector_ids: List[str] = field(default_factory=list)
    semantic_fingerprint: str = ""
    source_hash: str = ""
    project_fingerprint: str = ""
    rule_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
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
            "proof_obligation": self.proof_obligation,
            "regression_recipe": self.regression_recipe,
            "source": self.source,
            "playbook_id": self.playbook_id,
            "references": list(self.references),
            "evidence": list(self.evidence),
            "related_detector_ids": list(self.related_detector_ids),
            "semantic_fingerprint": self.semantic_fingerprint,
            "source_hash": self.source_hash,
            "project_fingerprint": self.project_fingerprint,
            "rule_version": self.rule_version,
        }

    def to_issue(self) -> Issue:
        issue = Issue(
            id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            file=self.file,
            line=self.line,
            snippet=self.snippet,
            description=self.description,
            exploit_scenario=self.exploit_scenario,
            remediation=self.remediation,
            references=list(self.references),
            language=self.language,
            review_status="MANUAL_PROOF",
            review_reasoning=f"Lens: autonomous/{self.source}. Proof obligation: {self.proof_obligation}",
            review_test=self.regression_recipe,
            review_engine="SELF autonomous reasoner",
            project_fingerprint=self.project_fingerprint,
            semantic_fingerprint=self.semantic_fingerprint,
            source_hash=self.source_hash,
            rule_version=self.rule_version,
            confidence_reasons=list(self.evidence),
        )
        return issue


@dataclass
class ExploitPath:
    id: str
    title: str
    severity: str
    steps: List[str]
    entry_points: List[str]
    related_finding_ids: List[str]
    narrative: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "steps": list(self.steps),
            "entry_points": list(self.entry_points),
            "related_finding_ids": list(self.related_finding_ids),
            "narrative": self.narrative,
        }


@dataclass
class DependencyHit:
    id: str
    package: str
    version: str
    ecosystem: str
    severity: str
    title: str
    summary: str
    advisory_id: str
    source_file: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "advisory_id": self.advisory_id,
            "source_file": self.source_file,
            "references": list(self.references),
        }


@dataclass
class ProjectIngestion:
    root: str
    framework: Any
    files: list
    extra_source: list
    manifests: List[ManifestFile]
    lockfiles: List[ManifestFile]
    docs_text: str
    combined_source: str
    languages: List[str]


@dataclass
class TrainedIndex:
    schema_version: int
    built_at: str
    document_count: int
    term_document_frequency: Dict[str, int]
    documents: List[Dict[str, Any]]
    playbook_weights: Dict[str, float]
    sources: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "built_at": self.built_at,
            "document_count": self.document_count,
            "term_document_frequency": dict(self.term_document_frequency),
            "documents": list(self.documents),
            "playbook_weights": dict(self.playbook_weights),
            "sources": list(self.sources),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrainedIndex":
        return cls(
            schema_version=int(data.get("schema_version", 1)),
            built_at=str(data.get("built_at", "")),
            document_count=int(data.get("document_count", 0)),
            term_document_frequency=dict(data.get("term_document_frequency") or {}),
            documents=list(data.get("documents") or []),
            playbook_weights=dict(data.get("playbook_weights") or {}),
            sources=list(data.get("sources") or []),
        )


@dataclass
class AutonomousAudit:
    version: str
    target: str
    project_fingerprint: str
    understanding: ProtocolUnderstanding
    static_issues: List[Issue]
    findings: List[AutonomousFinding]
    exploit_paths: List[ExploitPath]
    dependencies: List[DependencyHit]
    retrieved: List[RetrievedDoc]
    trained_on: Dict[str, Any]
    llm_used: bool
    llm_error: str
    elapsed: float
    diagnostics: List[str] = field(default_factory=list)

    def all_issues(self) -> List[Issue]:
        converted = [finding.to_issue() for finding in self.findings]
        return list(self.static_issues) + converted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "SELF — Autonomous AI Auditor",
            "version": self.version,
            "target": self.target,
            "project_fingerprint": self.project_fingerprint,
            "llm_used": self.llm_used,
            "llm_error": self.llm_error,
            "elapsed": self.elapsed,
            "trained_on": dict(self.trained_on),
            "understanding": self.understanding.to_dict(),
            "static_issues": [issue.to_dict() for issue in self.static_issues],
            "findings": [finding.to_dict() for finding in self.findings],
            "exploit_paths": [path.to_dict() for path in self.exploit_paths],
            "dependencies": [hit.to_dict() for hit in self.dependencies],
            "retrieved": [doc.to_dict() for doc in self.retrieved],
            "diagnostics": list(self.diagnostics),
        }
