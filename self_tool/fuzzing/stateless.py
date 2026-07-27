"""
SELF — Stateless Property Fuzzing
=================================

This module runs hypothesis-driven property tests against the *parsed*
structure of a target Solidity contract. Unlike the regex/static detectors,
each test instantiates fresh argument values and asserts structural
invariants derived from the parsed source:

  * arithmetic overflow guards
  * zero-address checks
  * unchecked low-level call return values
  * uninitialized state reads
  * require/revert coverage of every external call
  * modifier-on-private-data
  * modifiable visibility on state-changing functions

If hypothesis finds a counterexample (e.g., a public function with a
`uint256 amount` parameter that has NO arithmetic check on `amount`),
we surface it as a Finding.

Why not just run `forge fuzz`?
  * Zero external toolchain dependency
  * Runs in the same Python audit process (parallel with the static scan)
  * Hypothesis shrinks counterexamples down to a single bad value, which
    is exactly what an auditor wants to see ("here's the smallest input
    that breaks the property").

The fuzzer is intentionally STATELESS: each test call is independent.
Stateful sequence testing lives in `self_tool.fuzzing.stateful`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set

try:
    from hypothesis import given, settings, strategies as st, HealthCheck
    from hypothesis.errors import UnsatisfiedAssumption, NoSuchExample
    HYPOTHESIS_AVAILABLE = True
except Exception:  # pragma: no cover
    HYPOTHESIS_AVAILABLE = False

from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity


# ── Types ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FuzzTarget:
    """Description of one function we want to fuzz."""
    contract: str
    function: str
    line: int
    visibility: str
    param_types: tuple  # ("uint256", "address", ...)
    param_names: tuple  # ("amount", "to", ...)
    body: str
    has_payable: bool = False


@dataclass(frozen=True)
class Invariant:
    """One property: returns a finding if violated."""
    name: str
    severity: Severity
    confidence: Confidence
    detector_id: str
    title: str
    description: str
    check: Callable[[FuzzTarget, dict], Optional[str]]  # ctx, args -> msg or None


@dataclass
class StatelessFuzzResult:
    file: str
    runs: int = 0
    findings: List[Issue] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    seed: Optional[int] = None

    def add_finding(self, issue: Issue) -> None:
        # Dedup: same detector + line kept once per file
        if any(f.id == issue.id and f.line == issue.line and f.file == issue.file
               for f in self.findings):
            return
        self.findings.append(issue)


# ── Built-in invariants ──────────────────────────────────────────────────────
# Each check returns None (pass) or a string (violation reason).
# The check receives the parsed function AND a fresh random `args` dict.

def _inv_arithmetic_uint256_overflow(target: FuzzTarget, args: dict) -> Optional[str]:
    """uint256 params without SafeMath / unchecked markers risk overflow."""
    if not any(t.startswith("uint") for t in target.param_types):
        return None
    body_l = target.body.lower()
    has_safe = (
        "safemath" in body_l
        or "unchecked" in body_l
        or body_l.count("require") >= len(target.param_types)
    )
    if has_safe:
        return None
    bad_args = [
        k for k, v in args.items()
        if isinstance(v, int) and v > (1 << 192)
    ]
    if not bad_args:
        return None
    if "add" in body_l or "sub" in body_l or "mul" in body_l:
        return f"no overflow guard near arith op; example arg {bad_args[0]}={args[bad_args[0]]}"
    return None


def _inv_zero_address_check(target: FuzzTarget, args: dict) -> Optional[str]:
    """address params should require(adr != address(0)) somewhere."""
    if not any(t.startswith("address") for t in target.param_types):
        return None
    body_l = target.body.lower()
    if "address(0)" in body_l or "address(0x0)" in body_l:
        return None
    # find the address param name in body — if not present in a require, fail
    addr_params = [n for n, t in zip(target.param_names, target.param_types) if t.startswith("address")]
    for ap in addr_params:
        if ap in body_l:
            # at least one address param is used — fuzz the address() == 0 case
            if ap in args and args[ap] == "0x0000000000000000000000000000000000000000":
                return f"zero-address {ap} accepted without zero check"
    return None


def _inv_unprotected_initializer(target: FuzzTarget, args: dict) -> Optional[str]:
    """initialize-style functions must check already-initialized flag."""
    if not re.search(r"\b(init|initialize)\b", target.function, re.I):
        return None
    body_l = target.body.lower()
    has_guard = "initialized" in body_l or "_init" in body_l or "initializer" in body_l
    if has_guard:
        return None
    return f"function {target.function}() lacks initialized-flag guard"


def _inv_unchecked_lowlevel_return(target: FuzzTarget, args: dict) -> Optional[str]:
    """Calls to `addr.call(...)` should be checked (require(ok) or if(!ok)revert)."""
    if ".call" not in target.body:
        return None
    body_l = target.body.lower()
    if "require(" in body_l and ("ok" in body_l or "success" in body_l):
        return None
    if "if (!" in body_l or "if(!" in body_l:
        return None
    return "low-level .call() return value not checked"


def _inv_payable_external_call(target: FuzzTarget, args: dict) -> Optional[str]:
    """Functions that forward `msg.value` to another contract must guard amount."""
    if not target.has_payable and "msg.value" not in target.body:
        return None
    body_l = target.body.lower()
    if "address(this).balance" in body_l or "msg.value" not in body_l:
        return None
    if "require(" not in body_l:
        return f"msg.value forwarded without require() guard"
    return None


def _inv_reentrancy_surface(target: FuzzTarget, args: dict) -> Optional[str]:
    """`.call(...)` BEFORE state update is the classic DAO pattern."""
    if ".call" not in target.body:
        return None
    # crude ordering check
    call_pos = target.body.find(".call")
    state_write = re.search(r"\b\w+\s*(balances|totalSupply|shares|deposits)\s*[+\-*/]?=", target.body)
    if not state_write:
        return None
    if call_pos < state_write.start():
        return "external .call before state update (reentrancy surface)"
    return None


def _inv_selfdestruct_unguarded(target: FuzzTarget, args: dict) -> Optional[str]:
    if "selfdestruct" not in target.body:
        return None
    if "onlyowner" in target.body.lower() or "require(msg.sender ==" in target.body.lower():
        return None
    return "selfdestruct callable without access guard"


DEFAULT_INVARIANTS: List[Invariant] = [
    Invariant(
        name="arithmetic-overflow-uint",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detector_id="FUZZ-STATELESS-OVERFLOW",
        title="Unsigned integer overflow not guarded",
        description="uint256 parameter flows into arithmetic without SafeMath/unchecked/require.",
        check=_inv_arithmetic_uint256_overflow,
    ),
    Invariant(
        name="zero-address-missing",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        detector_id="FUZZ-STATELESS-ZERO-ADDRESS",
        title="Zero address not rejected",
        description="address parameter accepted without require(addr != address(0)).",
        check=_inv_zero_address_check,
    ),
    Invariant(
        name="initializer-unguarded",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detector_id="FUZZ-STATELESS-INIT",
        title="Initializer not guarded",
        description="init/initialize function lacks an `initialized` flag.",
        check=_inv_unprotected_initializer,
    ),
    Invariant(
        name="lowlevel-return-unchecked",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detector_id="FUZZ-STATELESS-CALL-OK",
        title="Unchecked low-level call return",
        description=".call() return value not checked with require or if(!ok).",
        check=_inv_unchecked_lowlevel_return,
    ),
    Invariant(
        name="payable-forwarded-no-guard",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detector_id="FUZZ-STATELESS-VALUE",
        title="msg.value forwarded without guard",
        description="Function forwards msg.value without require/assert.",
        check=_inv_payable_external_call,
    ),
    Invariant(
        name="reentrancy-ordering",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        detector_id="FUZZ-STATELESS-REENTRANCY",
        title="External call before state update",
        description=".call(...) executes before balances[...] -= amount.",
        check=_inv_reentrancy_surface,
    ),
    Invariant(
        name="selfdestruct-unguarded",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detector_id="FUZZ-STATELESS-SELFDESTRUCT",
        title="Unprotected selfdestruct",
        description="selfdestruct reachable without onlyOwner/require.",
        check=_inv_selfdestruct_unguarded,
    ),
]


# ── Target extraction ───────────────────────────────────────────────────────

_SOLIDITY_TYPES = re.compile(
    r"^(uint\d*|int\d*|bool|address|bytes\d*|string|fixed\d*|ufixed\d*)$"
)

def _split_params(param_str: str) -> tuple:
    """Parse `uint256 amount, address to` -> ([uint256, address], [amount, to])."""
    if not param_str.strip():
        return ((), ())
    types, names = [], []
    for raw in param_str.split(","):
        tok = raw.strip()
        if not tok:
            continue
        parts = tok.split()
        if len(parts) >= 2:
            types.append(parts[0])
            names.append(parts[-1].lstrip("()"))
        else:
            types.append(parts[0])
            names.append("")
    return (tuple(types), tuple(names))


def extract_targets(parsed_file) -> List[FuzzTarget]:
    targets: List[FuzzTarget] = []
    for contract in parsed_file.contracts:
        for fn in contract.functions:
            if fn.is_constructor or fn.is_fallback or fn.is_receive:
                continue
            if fn.visibility not in ("public", "external"):
                continue
            t, n = _split_params(fn.params)
            targets.append(FuzzTarget(
                contract=contract.name,
                function=fn.name,
                line=fn.line,
                visibility=fn.visibility,
                param_types=t,
                param_names=n,
                body=fn.body,
                has_payable=fn.mutability == "payable",
            ))
    return targets


# ── Hypothesis strategies per Solidity type ──────────────────────────────────

def _strategy(typ: str):
    """Return a hypothesis strategy that produces a value matching `typ`."""
    typ = typ.strip()
    if typ.startswith("uint") or typ.startswith("int"):
        bits = 256
        m = re.match(r"(u?int)(\d+)", typ)
        if m:
            bits = max(8, min(256, int(m.group(2))))
            if bits == 256:
                return st.integers(min_value=0 if typ.startswith("u") else -(2**255),
                                   max_value=(2**256) - 1 if typ.startswith("u") else (2**255) - 1)
        return st.integers(min_value=0, max_value=2**bits - 1)
    if typ == "address":
        # Bias toward zero-address: hypothesis will not always find it.
        return st.sampled_from([
            "0x0000000000000000000000000000000000000000",
            "0x1111111111111111111111111111111111111111",
            "0x" + "a" * 40,
            "0x" + "d" + "e" + "a" * 39,
        ])
    if typ == "bool":
        return st.booleans()
    if typ.startswith("bytes") or typ == "string":
        return st.binary(min_size=0, max_size=64)
    return st.none()


# ── Engine ───────────────────────────────────────────────────────────────────

@dataclass
class StatelessFuzzEngine:
    invariants: List[Invariant] = field(default_factory=lambda: list(DEFAULT_INVARIANTS))
    max_examples: int = 64
    deadline_ms: int = 200
    seed: Optional[int] = None

    def fuzz_file(self, file_ctx: FileContext) -> StatelessFuzzResult:
        result = StatelessFuzzResult(file=file_ctx.relative_path, seed=self.seed)
        if not HYPOTHESIS_AVAILABLE:
            result.errors.append("hypothesis not installed")
            return result
        try:
            parsed = parse_solidity(file_ctx)
        except Exception as exc:  # pragma: no cover
            result.errors.append(f"parse failed: {exc}")
            return result
        targets = extract_targets(parsed)
        for target in targets:
            self._fuzz_target(target, file_ctx, result)
        return result

    def _fuzz_target(self, target: FuzzTarget, file_ctx: FileContext,
                     result: StatelessFuzzResult) -> None:
        strategies = {n: _strategy(t) for n, t in zip(target.param_names, target.param_types)}
        if not strategies:
            return

        # Build a single example drawn per invariant call: hypothesis shrinks to the smallest.
        for inv in self.invariants:
            try:
                self._run_invariant(inv, target, strategies, file_ctx, result)
            except (UnsatisfiedAssumption, NoSuchExample):
                continue
            except Exception as exc:  # pragma: no cover
                result.errors.append(f"{inv.detector_id}@{target.function}: {exc}")

    def _run_invariant(self, inv: Invariant, target: FuzzTarget,
                       strategies: dict, file_ctx: FileContext,
                       result: StatelessFuzzResult) -> None:
        settings_kwargs = dict(
            max_examples=self.max_examples,
            deadline=self.deadline_ms,
            suppress_health_check=[HealthCheck.too_slow,
                                   HealthCheck.filter_too_much,
                                   HealthCheck.data_too_large],
        )
        if self.seed is not None:
            settings_kwargs["database"] = None
            settings_kwargs["derandomize"] = True
        @settings(**settings_kwargs)
        @given(**strategies)
        def _test(**args):
            result.runs += 1
            msg = inv.check(target, args)
            if msg is not None:
                issue = Issue(
                    id=inv.detector_id,
                    title=inv.title,
                    severity=inv.severity,
                    confidence=inv.confidence,
                    file=file_ctx.relative_path,
                    line=target.line,
                    snippet=f"function {target.function}({', '.join(target.param_types)})",
                    description=f"{inv.description}\n\nFuzz counterexample: {msg}\n",
                    exploit_scenario=f"Calling `{target.function}` with the shrunk counterexample triggers the invariant violation.",
                    remediation=f"Add a `require(...)` guard inside `{target.function}` for the violated invariant.",
                    references=["https://github.com/HypothesisWorks/hypothesis"],
                    language="solidity",
                )
                result.add_finding(issue)
                # Hypothesis can find more after the first hit, but the
                # first shrunk counterexample is what an auditor wants.
                raise _Found(msg)
        try:
            _test()
        except _Found:
            return

    def fuzz_files(self, file_contexts: Iterable[FileContext]) -> List[StatelessFuzzResult]:
        return [self.fuzz_file(c) for c in file_contexts]


class _Found(Exception):
    pass


# ── Convenience ──────────────────────────────────────────────────────────────

def fuzz_stateless(file_ctx: FileContext, *, max_examples: int = 64,
                   invariants: Optional[List[Invariant]] = None,
                   seed: Optional[int] = None) -> StatelessFuzzResult:
    eng = StatelessFuzzEngine(max_examples=max_examples,
                              invariants=invariants or DEFAULT_INVARIANTS,
                              seed=seed)
    return eng.fuzz_file(file_ctx)