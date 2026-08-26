"""Symbolic reasoner: apply trained playbooks to a project understanding."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from self_tool.autonomous.deep_scan import locate_deep
from self_tool.autonomous.models import (
    AutonomousFinding,
    Playbook,
    ProtocolUnderstanding,
)
from self_tool.core.fingerprints import semantic_fingerprint, source_context_hash
from self_tool.core.issue import Issue
from self_tool.core.scanner import FileContext
from self_tool.core.versions import RULE_VERSION


def reason(
    understanding: ProtocolUnderstanding,
    playbooks: Sequence[Playbook],
    files: Sequence[FileContext],
    static_issues: Sequence[Issue],
    project_fingerprint: str,
) -> List[AutonomousFinding]:
    combined = "\n".join(ctx.content for ctx in files)
    by_path = {ctx.relative_path: ctx for ctx in files}
    fired_detectors = {issue.id for issue in static_issues}
    findings: List[AutonomousFinding] = []
    seen: Set[Tuple[str, str, int]] = set()
    for playbook in playbooks:
        if playbook.id in set(understanding.accepted_playbooks or []):
            continue
        if playbook.languages and not (set(playbook.languages) & set(understanding.languages)):
            continue
        if playbook.protocol_types and not (set(playbook.protocol_types) & set(understanding.types)):
            # still allow if facts fire hard
            if not _facts_match(playbook, understanding):
                continue
        if not _patterns_match(playbook, combined):
            continue
        if playbook.fact_predicates and not _facts_match(playbook, understanding):
            continue
        location = _locate(playbook, files, understanding)
        if location[0] and _path_out_of_scope(location[0], understanding):
            continue
        key = (playbook.id, location[0], location[1])
        if key in seen:
            continue
        seen.add(key)
        snippet = ""
        ctx = by_path.get(location[0])
        if ctx:
            snippet = ctx.get_snippet(location[1], context=3)
        corroborated = sorted(set(playbook.related_detectors) & fired_detectors)
        confidence = "High" if corroborated or playbook.weight >= 1.2 else (
            "Medium" if playbook.weight >= 0.8 else "Low"
        )
        if playbook.weight < 0.4:
            continue
        source_text = snippet or playbook.id
        finding = AutonomousFinding(
            id=_finding_id(playbook),
            title=playbook.title,
            severity=playbook.severity,
            confidence=confidence,
            file=location[0],
            line=location[1],
            language=location[2],
            snippet=snippet,
            description=_describe(playbook, understanding, corroborated),
            exploit_scenario=playbook.exploit,
            remediation=playbook.remediation,
            proof_obligation=playbook.proof_obligation,
            regression_recipe=_regression(playbook),
            source="symbolic",
            playbook_id=playbook.id,
            references=_references(playbook),
            evidence=_evidence(playbook, understanding, corroborated),
            related_detector_ids=corroborated,
            semantic_fingerprint=semantic_fingerprint(
                playbook.id, RULE_VERSION,
                {"playbook": playbook.id, "file": location[0], "fn": location[3]},
            ),
            source_hash=source_context_hash(location[0], location[1], location[1], source_text),
            project_fingerprint=project_fingerprint,
            rule_version=RULE_VERSION,
        )
        findings.append(finding)
    findings.sort(key=lambda item: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(item.severity, 9),
        item.file, item.line, item.id,
    ))
    return findings


def _facts_match(playbook: Playbook, understanding: ProtocolUnderstanding) -> bool:
    if not playbook.fact_predicates:
        return True
    return all(understanding.facts.get(name, False) for name in playbook.fact_predicates)


def _patterns_match(playbook: Playbook, combined: str) -> bool:
    if playbook.required_all_patterns:
        if not all(_contains(combined, pat) for pat in playbook.required_all_patterns):
            return False
    if playbook.required_any_patterns:
        if not any(_contains(combined, pat) for pat in playbook.required_any_patterns):
            return False
    if playbook.forbidden_patterns:
        if all(_contains(combined, pat) for pat in playbook.forbidden_patterns):
            return False
    return True


_WORD_BOUND_PATTERNS = {"sqrtp", "basel"}
_SKIP_PATH_RE = re.compile(r"(^|/)(interfaces?|mocks?)/", re.IGNORECASE)
_CONST_FILE_RE = re.compile(r"constants?\.sol$", re.IGNORECASE)
_DEEP_PLAYBOOK_FACTS = {
    "AV-ARBITRARY-ERC20-FROM": "arbitrary_erc20_from",
    "AV-ARBITRARY-ETH-SEND": "arbitrary_eth_receiver",
    "AV-MSG-VALUE-LOOP": "msg_value_in_loop",
    "AV-LOCKED-ETHER": "locked_ether",
    "AV-ENCODEPACKED-COLLISION": "encode_packed_collision",
    "AV-UNCHECKED-CALL": "unchecked_lowlevel_call",
    "AV-BALANCE-EQ": "balance_strict_eq",
    "AV-MAPPING-DELETE": "mapping_delete_struct",
    # Protocol-math / invariant lens.
    "AV-SECOND-ORDER-REENTRANCY": "second_order_reentrancy",
    "AV-MISSING-ACCRUE": "missing_accrue_on_value_path",
    "AV-MISSING-SHARE-INVARIANT": "missing_share_invariant",
    "AV-MISSING-K": "missing_k_invariant",
    "AV-TSTORE-DELETE-POISON": "tstore_delete_poison",
}


def _combined_from(understanding: ProtocolUnderstanding, files: Sequence[FileContext]) -> str:
    if understanding.source_chars:
        return "\n".join(ctx.content for ctx in files)
    return ""


def _contains(text: str, pattern: str) -> bool:
    if not pattern:
        return True
    if pattern.lower() in _WORD_BOUND_PATTERNS:
        return re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(pattern)}(?![A-Za-z0-9_])",
            text,
            re.IGNORECASE,
        ) is not None
    return pattern.lower() in text.lower()


def _path_out_of_scope(path: str, understanding: ProtocolUnderstanding) -> bool:
    listed = list(understanding.out_of_scope_paths or [])
    if not listed:
        return False
    try:
        from self_tool.core.doc_reader import path_is_listed
        return path_is_listed(path, listed)
    except Exception:
        return False


def _skip_file(file_ctx: FileContext) -> bool:
    path = file_ctx.relative_path.replace("\\", "/")
    if _SKIP_PATH_RE.search(path) or _CONST_FILE_RE.search(path):
        return True
    if re.search(r"^\s*interface\s+\w+", file_ctx.content, re.MULTILINE) and not re.search(
        r"^\s*(abstract\s+)?contract\s+\w+", file_ctx.content, re.MULTILINE
    ):
        return True
    return False


def _locate(
    playbook: Playbook,
    files: Sequence[FileContext],
    understanding: ProtocolUnderstanding,
) -> Tuple[str, int, str, str]:
    if playbook.id == "AV-ACCESS-MISSING":
        located = _locate_unguarded_admin(understanding)
        if located:
            return located
    fact = _DEEP_PLAYBOOK_FACTS.get(playbook.id)
    if fact:
        located = locate_deep(understanding.contracts, fact, _combined_from(understanding, files))
        if located:
            return located
    needles = list(playbook.required_any_patterns) + list(playbook.required_all_patterns)
    allowed = set(playbook.languages) if playbook.languages else None
    for file_ctx in files:
        if _skip_file(file_ctx) or _path_out_of_scope(file_ctx.relative_path, understanding):
            continue
        if allowed and file_ctx.language not in allowed:
            continue
        for needle in needles:
            if not needle:
                continue
            if needle.lower() in _WORD_BOUND_PATTERNS:
                match = re.search(
                    rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])",
                    file_ctx.content,
                    re.IGNORECASE,
                )
                if not match:
                    continue
                idx = match.start()
            else:
                idx = file_ctx.content.lower().find(needle.lower())
                if idx < 0:
                    continue
            line = file_ctx.content[:idx].count("\n") + 1
            fn = _function_near(understanding, file_ctx.relative_path, line)
            return file_ctx.relative_path, line, file_ctx.language, fn
    impl = [ctx for ctx in files if not _skip_file(ctx) and not _path_out_of_scope(ctx.relative_path, understanding)]
    pool = impl or list(files)
    if pool:
        fn = understanding.permissionless_ops[0] if understanding.permissionless_ops else ""
        return pool[0].relative_path, 1, pool[0].language, fn
    return "", 0, "", ""


def _locate_unguarded_admin(
    understanding: ProtocolUnderstanding,
) -> Optional[Tuple[str, int, str, str]]:
    admin_word = re.compile(
        r"owner|admin|upgrade|pause|unpause|sweep|rescue|grantRole|"
        r"revokeRole|transferOwnership|selfdestruct|destroy",
        re.IGNORECASE,
    )
    for contract in understanding.contracts:
        if contract.kind in {"interface", "library"}:
            continue
        for func in contract.functions:
            if not (re.match(r"set[A-Z]", func.name) or admin_word.search(func.name)):
                continue
            mods = {item.lower() for item in func.modifiers}
            if any(item.startswith("only") or item.endswith("auth") or item.endswith("role") for item in mods):
                continue
            if re.search(
                r"msg\.sender\s*==|require\s*\(\s*msg\.sender|onlyOwner|hasRole",
                func.body,
                re.IGNORECASE,
            ):
                continue
            return func.file, func.line, func.language, f"{contract.name}.{func.name}"
    return None


def _function_near(understanding: ProtocolUnderstanding, file: str, line: int) -> str:
    best = ""
    best_delta = 10**9
    for contract in understanding.contracts:
        if contract.file != file:
            continue
        for func in contract.functions:
            delta = abs(func.line - line)
            if delta < best_delta:
                best_delta = delta
                best = f"{contract.name}.{func.name}"
    return best


def _finding_id(playbook: Playbook) -> str:
    # Stable, catalog-independent id. review_issues is never called on these.
    suffix = playbook.id.replace("AV-", "")
    return f"AUTO-{suffix}"


def _describe(
    playbook: Playbook,
    understanding: ProtocolUnderstanding,
    corroborated: Sequence[str],
) -> str:
    bits = [
        playbook.description,
        f"Project understanding: {understanding.summary}",
    ]
    incidents = list(playbook.real_incidents)
    try:
        from self_tool.autonomous.brain import incidents_for_playbook
        for name in incidents_for_playbook(playbook.id):
            if name not in incidents:
                incidents.append(name)
    except Exception:
        pass
    if incidents:
        bits.append("Trained on incidents: " + ", ".join(incidents) + ".")
    if corroborated:
        bits.append("Corroborated by static detectors: " + ", ".join(corroborated) + ".")
    return " ".join(bits)


def _references(playbook: Playbook) -> List[str]:
    refs = []
    if playbook.owasp:
        refs.append(playbook.owasp)
    refs.extend(playbook.cwe)
    refs.extend(playbook.swc)
    return refs


def _evidence(
    playbook: Playbook,
    understanding: ProtocolUnderstanding,
    corroborated: Sequence[str],
) -> List[str]:
    evidence = [f"playbook={playbook.id}", f"weight={playbook.weight:.2f}"]
    for pred in playbook.fact_predicates:
        evidence.append(f"fact:{pred}={understanding.facts.get(pred)}")
    if corroborated:
        evidence.append("corroborated=" + ",".join(corroborated))
    return evidence


def _regression(playbook: Playbook) -> str:
    if playbook.related_detectors:
        return f"forge test --match-test {playbook.related_detectors[0].replace('-', '_')} -vvvv"
    return f"Add a Foundry/Anchor/Move test that reproduces {playbook.id} and assert the defensive pattern holds."
