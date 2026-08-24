"""Optional LLM backend for the autonomous auditor.

Imported only when the user passes ``--llm``. Never imported by the
default scan path. Network is opt-in and fails closed: any error is
returned to the pipeline, which keeps the symbolic findings.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

from self_tool.autonomous.models import (
    AutonomousFinding,
    ProtocolUnderstanding,
    RetrievedDoc,
)
from self_tool.core.fingerprints import semantic_fingerprint, source_context_hash
from self_tool.core.issue import Issue
from self_tool.core.versions import RULE_VERSION


PROVIDERS = ("auto", "openai", "anthropic", "ollama")
MAX_BRIEF = 12000
TIMEOUT = 45


class LLMError(RuntimeError):
    pass


def refine_with_llm(
    *,
    understanding: ProtocolUnderstanding,
    static_issues: Sequence[Issue],
    findings: Sequence[AutonomousFinding],
    retrieved: Sequence[RetrievedDoc],
    known_files: Sequence[str],
    provider: str = "auto",
    project_fingerprint: str,
) -> Tuple[List[AutonomousFinding], str]:
    """Ask an LLM to add business-logic findings grounded in the briefing.

    Returns (new_findings, error_string). error_string is empty on success.
    """
    try:
        name, payload = _dispatch(provider)
        briefing = _briefing(understanding, static_issues, findings, retrieved)
        raw = _complete(name, payload, briefing)
        extra = _parse_findings(raw, known_files, project_fingerprint)
        return extra, ""
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _dispatch(provider: str) -> Tuple[str, Dict[str, str]]:
    provider = (provider or "auto").lower()
    if provider not in PROVIDERS:
        raise LLMError(f"unknown provider {provider}")
    if provider in {"auto", "openai"} and os.environ.get("OPENAI_API_KEY"):
        return "openai", {
            "api_key": os.environ["OPENAI_API_KEY"],
            "base": os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1",
            "model": os.environ.get("SELF_LLM_MODEL") or "gpt-4o-mini",
        }
    if provider in {"auto", "anthropic"} and os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", {
            "api_key": os.environ["ANTHROPIC_API_KEY"],
            "model": os.environ.get("SELF_LLM_MODEL") or "claude-3-5-haiku-latest",
        }
    if provider in {"auto", "ollama"} and (
        os.environ.get("OLLAMA_HOST") or provider == "ollama"
    ):
        return "ollama", {
            "base": os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434",
            "model": os.environ.get("SELF_LLM_MODEL") or "llama3.1",
        }
    raise LLMError(
        "no LLM credentials. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_HOST."
    )


def _briefing(
    understanding: ProtocolUnderstanding,
    static_issues: Sequence[Issue],
    findings: Sequence[AutonomousFinding],
    retrieved: Sequence[RetrievedDoc],
) -> str:
    static = [
        f"- {issue.severity} {issue.id} {issue.title} @ {issue.file}:{issue.line}"
        for issue in static_issues[:25]
    ]
    auto = [
        f"- {item.severity} {item.id} {item.title} @ {item.file}:{item.line}"
        for item in findings[:25]
    ]
    knowledge = [f"- {doc.kind} {doc.doc_id}: {doc.title}" for doc in retrieved]
    text = "\n".join([
        "You are a defensive smart-contract auditor. Return ONLY JSON.",
        "Schema: {\"findings\":[{\"title\":\"\",\"severity\":\"HIGH\",",
        "\"file\":\"relative/path\",\"line\":1,\"language\":\"solidity\",",
        "\"description\":\"\",\"exploit_scenario\":\"\",\"remediation\":\"\",",
        "\"proof_obligation\":\"\"}]}",
        "Do not invent files. Only cite files listed in the understanding.",
        "Focus on business logic, math, and multi-step economic attacks",
        "that the static list may have missed. Max 8 findings.",
        "",
        understanding.briefing(limit=3500),
        "",
        "Static findings:",
        "\n".join(static) or "- none",
        "",
        "Symbolic findings:",
        "\n".join(auto) or "- none",
        "",
        "Retrieved knowledge:",
        "\n".join(knowledge) or "- none",
    ])
    return text[:MAX_BRIEF]


def _complete(provider: str, payload: Dict[str, str], briefing: str) -> str:
    if provider == "openai":
        body = {
            "model": payload["model"],
            "temperature": 0,
            "messages": [
                {"role": "system", "content": "Return only valid JSON."},
                {"role": "user", "content": briefing},
            ],
        }
        url = payload["base"].rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {payload['api_key']}",
            "Content-Type": "application/json",
        }
        data = _http_json(url, body, headers)
        return data["choices"][0]["message"]["content"]
    if provider == "anthropic":
        body = {
            "model": payload["model"],
            "max_tokens": 2000,
            "temperature": 0,
            "messages": [{"role": "user", "content": briefing}],
        }
        headers = {
            "x-api-key": payload["api_key"],
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        data = _http_json("https://api.anthropic.com/v1/messages", body, headers)
        parts = data.get("content") or []
        return "".join(part.get("text", "") for part in parts if isinstance(part, dict))
    # ollama
    body = {
        "model": payload["model"],
        "stream": False,
        "prompt": briefing,
    }
    data = _http_json(payload["base"].rstrip("/") + "/api/generate", body, {
        "Content-Type": "application/json",
    })
    return data.get("response") or ""


def _http_json(url: str, body: dict, headers: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise LLMError(f"request failed: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"provider returned non-JSON: {exc}") from exc


def _parse_findings(
    raw: str,
    known_files: Sequence[str],
    project_fingerprint: str,
) -> List[AutonomousFinding]:
    payload = _extract_json(raw)
    items = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise LLMError("response JSON missing findings list")
    known = set(known_files)
    out: List[AutonomousFinding] = []
    for index, item in enumerate(items[:8]):
        if not isinstance(item, dict):
            continue
        path = str(item.get("file") or "")
        if known and path not in known:
            continue
        severity = str(item.get("severity") or "MEDIUM").upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "MEDIUM"
        title = str(item.get("title") or "LLM finding")[:160]
        line = int(item.get("line") or 0)
        language = str(item.get("language") or "solidity")
        finding_id = f"AUTO-LLM-{index + 1:03d}"
        out.append(AutonomousFinding(
            id=finding_id,
            title=title,
            severity=severity,
            confidence="Low",
            file=path,
            line=line,
            language=language,
            snippet="",
            description=str(item.get("description") or "")[:2000],
            exploit_scenario=str(item.get("exploit_scenario") or "")[:2000],
            remediation=str(item.get("remediation") or "")[:2000],
            proof_obligation=str(item.get("proof_obligation") or "Manually prove or refute the LLM claim against source.")[:2000],
            regression_recipe="Write a failing test that encodes the claimed invariant, then fix the code.",
            source="llm",
            playbook_id="LLM",
            evidence=["llm-proposed", "unverified"],
            semantic_fingerprint=semantic_fingerprint(
                finding_id, RULE_VERSION, {"title": title, "file": path},
            ),
            source_hash=source_context_hash(path, line, line, title),
            project_fingerprint=project_fingerprint,
            rule_version=RULE_VERSION,
        ))
    return out


def _extract_json(raw: str) -> Any:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise LLMError("could not parse JSON from model output")
