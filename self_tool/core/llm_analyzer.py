"""
SELF — Local LLM Analyzer via Ollama
Sends flagged findings to a local LLM for intelligent false-positive filtering
and deep reasoning about complex vulnerabilities.

Zero cloud. Zero API key. Runs on your machine.
Requires: ollama (pip install ollama) + Ollama server running + a model pulled.

Recommended models:
  deepseek-coder:6.7b  — Best code reasoning, ~4GB RAM (recommended)
  qwen2.5-coder:7b     — Excellent, latest 2024, ~4GB RAM
  codellama:7b         — Solid fallback, ~4GB RAM
  llama3.1:8b          — General reasoning, ~5GB RAM

Install:
  curl -fsSL https://ollama.ai/install.sh | sh
  ollama pull deepseek-coder:6.7b
"""

import json
import time
from typing import List, Optional, Tuple
from dataclasses import dataclass

from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.protocol_context import ProtocolContext


# ── Constants ──────────────────────────────────────────────────────────────

DEFAULT_MODEL = "deepseek-coder:6.7b"
DEFAULT_TIMEOUT = 90   # seconds per finding
MAX_SNIPPET_LEN = 1500 # characters of code to send

VERDICT_CONFIRMED  = "CONFIRMED"
VERDICT_LIKELY_FP  = "LIKELY_FALSE_POSITIVE"
VERDICT_UNCERTAIN  = "UNCERTAIN"


@dataclass
class AIVerdict:
    verdict: str            # CONFIRMED / LIKELY_FALSE_POSITIVE / UNCERTAIN
    reasoning: str          # 2-3 sentence explanation
    severity_adjustment: str  # "upgrade" / "downgrade" / "keep"
    model: str
    elapsed_seconds: float


# ── Prompt templates ───────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert smart contract security auditor with deep knowledge of:
- Common vulnerability patterns (reentrancy, access control, oracle manipulation, etc.)
- Real-world exploit incidents (Rekt.news, Immunefi, Code4rena, Sherlock)
- DeFi protocol mechanics (AMMs, lending, bridges, staking, governance)
- Solidity, Vyper, Rust/Anchor, Huff, and Move languages

Your job is to review a security finding flagged by a static analysis tool and determine:
1. Is this a REAL vulnerability or a false positive?
2. Does the surrounding code context or protocol documentation contradict the finding?
3. Should the severity be adjusted?

Be precise, brief, and honest. Acknowledge uncertainty when present.
NEVER hallucinate vulnerability details not present in the provided code."""

FINDING_PROMPT_TEMPLATE = """## Protocol Context
{protocol_context}

## Flagged Code ({file}:{line})
```solidity
{code_snippet}
```

## Static Analysis Finding
**ID:** {finding_id}
**Severity:** {severity}
**Title:** {title}
**Description:** {description}
**Exploit Scenario:** {exploit_scenario}

## Your Task
Analyze the flagged code against the protocol context and determine:

1. **Verdict** (choose exactly one):
   - CONFIRMED: This is a real vulnerability based on the code
   - LIKELY_FALSE_POSITIVE: The code, context, or docs suggest this is not exploitable
   - UNCERTAIN: Not enough context to determine with confidence

2. **Reasoning**: In 2-3 sentences, explain WHY you chose this verdict. Reference specific code patterns or doc signals.

3. **Severity Adjustment** (choose one): upgrade | downgrade | keep

Respond ONLY in this JSON format:
```json
{{
  "verdict": "CONFIRMED|LIKELY_FALSE_POSITIVE|UNCERTAIN",
  "reasoning": "Your 2-3 sentence explanation here.",
  "severity_adjustment": "upgrade|downgrade|keep"
}}
```"""


# ── Ollama connector ───────────────────────────────────────────────────────

class OllamaConnector:
    """Thin wrapper around the Ollama Python SDK."""

    def __init__(self, model: str = DEFAULT_MODEL, timeout: int = DEFAULT_TIMEOUT):
        self.model = model
        self.timeout = timeout
        self._client = None
        self._available = None

    def is_available(self) -> Tuple[bool, str]:
        """Check if Ollama is running and the model is available."""
        if self._available is not None:
            return self._available

        try:
            import ollama  # type: ignore[import]
            response = ollama.list()

            # Handle both old API (dict) and new API (ListResponse object)
            if hasattr(response, 'models'):
                # New SDK: ListResponse with .models list of Model objects
                raw_models = response.models
                model_names = []
                for m in raw_models:
                    name = getattr(m, 'model', None) or getattr(m, 'name', None)
                    if name:
                        model_names.append(str(name))
            else:
                # Old SDK: plain dict {'models': [{'name': ...}]}
                raw_models = response.get('models', [])
                model_names = [
                    m.get('name', m.get('model', '')) for m in raw_models
                ]
            model_names = [n for n in model_names if n]  # remove blanks

            if not model_names:
                self._available = (False, "No models pulled. Run: ollama pull deepseek-coder:6.7b")
                return self._available

            # Check if requested model is available (partial match)
            available = any(self.model.split(':')[0] in name for name in model_names)
            if not available:
                # Fall back to first available model
                self.model = model_names[0]

            self._client = ollama
            self._available = (True, f"Ollama ready. Model: {self.model}")
            return self._available

        except ImportError:
            self._available = (False, "Ollama SDK not installed. Run: pip install ollama")
            return self._available
        except Exception as e:
            err = str(e)
            if 'connection' in err.lower() or 'refused' in err.lower():
                msg = "Ollama server not running. Run: ollama serve"
            else:
                msg = f"Ollama error: {err}"
            self._available = (False, msg)
            return self._available

    def query(self, prompt: str, system: str = SYSTEM_PROMPT) -> Optional[str]:
        """Send a prompt to Ollama and return the response text."""
        try:
            import ollama  # type: ignore[import]
            response = ollama.chat(
                model=self.model,
                messages=[
                    {'role': 'system', 'content': system},
                    {'role': 'user',   'content': prompt},
                ],
                options={
                    'temperature': 0.1,    # Low temp = consistent, factual
                    'top_p': 0.9,
                    'num_predict': 400,    # Max tokens to generate
                },
            )
            # Handle both old API (dict) and new API (ChatResponse object)
            if hasattr(response, 'message'):
                msg = response.message
                return getattr(msg, 'content', None) or str(msg)
            return response['message']['content']
        except Exception as e:
            return None


# ── AI Analyzer ───────────────────────────────────────────────────────────

class LLMAnalyzer:
    """
    Runs each flagged finding through a local LLM for intelligent review.
    Enriches issues with AI verdict and reasoning.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        timeout: int = DEFAULT_TIMEOUT,
        analyze_severity: Optional[List[str]] = None,  # None = CRITICAL+HIGH only
    ):
        self.connector = OllamaConnector(model=model, timeout=timeout)
        # Default: only analyze Critical and High (fast)
        self.analyze_severity = analyze_severity or [Severity.CRITICAL, Severity.HIGH]

    def check(self) -> Tuple[bool, str]:
        """Return (is_available, status_message)."""
        return self.connector.is_available()

    def analyze(
        self,
        issues: List[Issue],
        protocol_ctx: ProtocolContext,
        progress_callback=None,
    ) -> List[Issue]:
        """
        Enrich issues with AI verdicts. Returns the same list with
        ai_verdict, ai_reasoning, and possibly adjusted confidence.
        """
        available, msg = self.connector.is_available()
        if not available:
            return issues

        to_analyze = [i for i in issues if i.severity in self.analyze_severity]

        for idx, issue in enumerate(to_analyze):
            if progress_callback:
                progress_callback(idx, len(to_analyze), issue)

            verdict = self._analyze_one(issue, protocol_ctx)
            if verdict:
                issue.ai_verdict = verdict.verdict
                issue.ai_reasoning = verdict.reasoning
                issue.ai_model = verdict.model

                # Apply severity adjustment
                if verdict.severity_adjustment == "downgrade":
                    issue.confidence = Confidence.LOW
                elif verdict.severity_adjustment == "upgrade":
                    if issue.confidence == Confidence.LOW:
                        issue.confidence = Confidence.MEDIUM
                    elif issue.confidence == Confidence.MEDIUM:
                        issue.confidence = Confidence.HIGH

                # Mark likely false positives
                if verdict.verdict == VERDICT_LIKELY_FP:
                    issue.suppressed = True
                    issue.suppression_reason = f"AI: {verdict.reasoning}"

        return issues

    def _analyze_one(self, issue: Issue, ctx: ProtocolContext) -> Optional[AIVerdict]:
        """Analyze a single finding. Returns AIVerdict or None on failure."""
        t_start = time.time()

        # Build prompt
        snippet = issue.snippet[:MAX_SNIPPET_LEN] if issue.snippet else "(no snippet available)"
        prompt = FINDING_PROMPT_TEMPLATE.format(
            protocol_context=ctx.get_llm_summary(),
            file=issue.file,
            line=issue.line,
            code_snippet=snippet,
            finding_id=issue.id,
            severity=issue.severity,
            title=issue.title,
            description=issue.description[:500],
            exploit_scenario=issue.exploit_scenario[:300],
        )

        response = self.connector.query(prompt)
        elapsed = time.time() - t_start

        if not response:
            return None

        verdict, reasoning, adjustment = self._parse_response(response)
        return AIVerdict(
            verdict=verdict,
            reasoning=reasoning,
            severity_adjustment=adjustment,
            model=self.connector.model,
            elapsed_seconds=elapsed,
        )

    @staticmethod
    def _parse_response(response: str) -> Tuple[str, str, str]:
        """Parse LLM JSON response. Robust to partial/malformed output."""
        # Try to extract JSON block
        json_match = None
        for pattern in [
            r'```json\s*(\{.*?\})\s*```',
            r'```\s*(\{.*?\})\s*```',
            r'(\{[^{}]*"verdict"[^{}]*\})',
        ]:
            import re
            m = re.search(pattern, response, re.DOTALL)
            if m:
                json_match = m.group(1)
                break

        if json_match:
            try:
                data = json.loads(json_match)
                verdict = data.get('verdict', VERDICT_UNCERTAIN).upper()
                if verdict not in (VERDICT_CONFIRMED, VERDICT_LIKELY_FP, VERDICT_UNCERTAIN):
                    verdict = VERDICT_UNCERTAIN
                reasoning = data.get('reasoning', 'No reasoning provided.')[:500]
                adjustment = data.get('severity_adjustment', 'keep').lower()
                if adjustment not in ('upgrade', 'downgrade', 'keep'):
                    adjustment = 'keep'
                return verdict, reasoning, adjustment
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback: heuristic parsing from plain text
        response_lower = response.lower()
        if 'confirmed' in response_lower and 'false positive' not in response_lower:
            verdict = VERDICT_CONFIRMED
        elif 'false positive' in response_lower or 'not exploitable' in response_lower:
            verdict = VERDICT_LIKELY_FP
        else:
            verdict = VERDICT_UNCERTAIN

        # Extract first sentence as reasoning
        sentences = [s.strip() for s in response.split('.') if len(s.strip()) > 10]
        reasoning = '. '.join(sentences[:2]) + '.' if sentences else response[:200]

        return verdict, reasoning[:500], 'keep'


# ── Convenience function ───────────────────────────────────────────────────

def create_analyzer(
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT,
    analyze_all: bool = False,
) -> LLMAnalyzer:
    """Factory function for the CLI."""
    severity_filter = None if analyze_all else [Severity.CRITICAL, Severity.HIGH]
    return LLMAnalyzer(model=model, timeout=timeout, analyze_severity=severity_filter)
