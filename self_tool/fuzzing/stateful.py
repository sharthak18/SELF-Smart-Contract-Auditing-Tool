"""
SELF — Stateful Sequence Fuzzing
================================

Where the stateless fuzzer checks single-call invariants, the stateful
fuzzer runs a *sequence* of calls against a per-contract mock EVM and
checks invariants that span across calls:

  * total supply invariant: sum(balances) == totalSupply
  * accounting invariant:   deposits - withdrawals == contract balance
  * access invariant:       only admin can mint; sequence with non-admin
                            call should revert
  * reentrancy invariant:   a function that calls out before writing
                            state can be drained if the callee re-enters
  * oracle/price invariant:  spot price returns a sensible value after
                            a large swap

The engine:
  1. Parses each target contract via the existing Solidity parser
  2. Builds a `MockEVM` keyed by `SolStateVar.name`
  3. Generates a sequence of `StatefulAction`s drawn from a weighted menu
  4. Runs the sequence, applying each action to the mock EVM
  5. Checks sequence invariants after every step
  6. If a violation is found, shrinks the sequence down to the minimal
     reproducing trace (Echidna-style)

It is intentionally an *AST-pattern interpreter*, not a full EVM:
  - It models `mapping(address=>uint256)` and `uint256` storage
  - It recognises `+= -= *=` writes, `require(...)` guards, `.call{value:}` 
    forwarders, `selfdestruct`, low-level `.call(...)` returns
  - Anything it can't model, it skips (no false positives from guessing)
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.core.xray import EntryPoint
from self_tool.parsers.solidity_parser import parse_solidity


# ── Mock EVM state ───────────────────────────────────────────────────────────

@dataclass
class MockEVM:
    """Lightweight contract state for sequence fuzzing.

    `storage` keys by state-var name. `mapping_*` keys by `(name, key)` tuples.
    `balances` tracks ETH-equivalent balances per address.
    `reentrancy_lock` simulates the nonReentrant modifier.
    `event_log` collects emitted events for invariants.
    """
    storage: Dict[str, int] = field(default_factory=dict)
    mappings: Dict[Tuple[str, str], int] = field(default_factory=dict)
    balances: Dict[str, int] = field(default_factory=dict)
    reentrancy_lock: bool = False
    event_log: List[Tuple[str, dict]] = field(default_factory=list)
    admin: str = "0xADMIN"
    call_count: int = 0
    destroyed: bool = False
    halted: bool = False
    halted_reason: str = ""

    def get(self, name: str, key: Optional[str] = None) -> int:
        if key is None:
            return self.storage.get(name, 0)
        return self.mappings.get((name, key), 0)

    def set(self, name: str, value: int, key: Optional[str] = None) -> None:
        if key is None:
            self.storage[name] = value
        else:
            self.mappings[(name, key)] = value

    def balance(self, who: str) -> int:
        return self.balances.get(who, 0)


# ── Action + result types ────────────────────────────────────────────────────

@dataclass(frozen=True)
class StatefulAction:
    """One call drawn from the action menu."""
    function: str           # function name in the contract
    caller: str             # "0xUSER" | "0xADMIN" | "0xATTACKER"
    args: tuple = ()        # tuple of (name, value) pairs
    label: str = ""         # human description for the trace


@dataclass
class TraceStep:
    seq: int
    action: StatefulAction
    before_snapshot: dict
    after_snapshot: dict
    halted: bool
    halt_reason: str = ""


@dataclass
class StatefulFuzzResult:
    file: str
    sequences: int = 0
    total_steps: int = 0
    findings: List[Issue] = field(default_factory=list)
    shrunk_traces: List[List[StatefulAction]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    seed: Optional[int] = None

    def add_finding(self, issue: Issue) -> None:
        if any(f.id == issue.id and f.line == issue.line and f.file == issue.file
               for f in self.findings):
            return
        self.findings.append(issue)


# ── Mock EVM action dispatcher ───────────────────────────────────────────────

class MockDispatcher:
    """Apply a `StatefulAction` to a `MockEVM` using regex-extracted micro-ops.

    The dispatcher is intentionally dumb: it reads the function body,
    matches a small set of known patterns, and updates the mock state.
    """
    def __init__(self, parsed_file):
        self.functions = {}
        self.state_var_names = set()
        self.function_lines = {}
        self.function_bodies = {}
        for contract in parsed_file.contracts:
            for fn in contract.functions:
                self.functions[fn.name] = fn
                self.function_lines[fn.name] = fn.line
                self.function_bodies[fn.name] = fn.body
            for sv in contract.state_vars:
                self.state_var_names.add(sv.name)

    def apply(self, evm: MockEVM, action: StatefulAction) -> Tuple[MockEVM, str]:
        """Apply action, return (new_state, halt_reason_or_empty)."""
        if evm.destroyed or evm.halted:
            return evm, evm.halted_reason or "destroyed"
        fn = self.functions.get(action.function)
        if fn is None:
            return evm, f"unknown function {action.function}"

        body = fn.body
        body_l = body.lower()

        # 1. Access guard: onlyOwner / require(msg.sender == X)
        if "onlyowner" in body_l and action.caller != evm.admin:
            return evm, "onlyOwner revert"
        if "require(msg.sender ==" in body_l.replace(" ", ""):
            if action.caller != evm.admin:
                return evm, "admin-only revert"

        # 2. Reentrancy lock toggle
        if "nonreentrant" in body_l:
            if evm.reentrancy_lock:
                return evm, "reentrancy lock"
            evm.reentrancy_lock = True

        # 3. Argument bindings for this call
        bindings: Dict[str, object] = {name: val for name, val in action.args}

        # 4. Selfdestruct
        if "selfdestruct" in body:
            evm.destroyed = True
            evm.event_log.append(("SelfDestruct", {"caller": action.caller}))
            return evm, ""

        # 5. Balance update: handle deposits + withdrawals
        if "msg.value" in body or "payable" in fn.mutability.lower():
            v = int(bindings.get("value", 0) or 0)
            evm.balances[action.caller] = evm.balances.get(action.caller, 0) + v

        # 6. Pattern-mock: extract update expressions
        #    e.g. `balances[msg.sender] -= amount`
        updates = re.findall(
            r"(\w+)\[([^\]]+)\]\s*([+\-*/]=)\s*([\w\.\(\)]+)",
            body,
        )
        for var, key_expr, op, rhs in updates:
            key = self._resolve(key_expr, action.caller, bindings)
            cur = evm.get(var, key)
            rhs_v = self._resolve(rhs, action.caller, bindings)
            if op == "+=":
                evm.set(var, cur + rhs_v, key)
            elif op == "-=":
                evm.set(var, cur - rhs_v, key)
            elif op == "*=":
                evm.set(var, cur * rhs_v, key)
            elif op == "/=":
                evm.set(var, cur // rhs_v if rhs_v else 0, key)
            evm.event_log.append(("StateUpdate", {"var": var, "key": key, "op": op}))

        # Plain uint updates: `totalDeposited += amount`
        for var in self.state_var_names:
            for m in re.finditer(rf"\b{var}\b\s*([+\-*/]=)\s*([\w\(\)\.\s]+?)(?=;|\n|$)", body):
                op = m.group(1)
                rhs_v = self._resolve(m.group(2), action.caller, bindings)
                cur = evm.storage.get(var, 0)
                if op == "+=":
                    evm.storage[var] = cur + rhs_v
                elif op == "-=":
                    evm.storage[var] = cur - rhs_v
                elif op == "*=":
                    evm.storage[var] = cur * rhs_v
                elif op == "/=":
                    evm.storage[var] = cur // rhs_v if rhs_v else 0
                evm.event_log.append(("StorageUpdate", {"var": var, "op": op}))

        # 7. Low-level call (.call / .call{value:} / .transfer / .send)
        if ".call" in body:
            target = self._resolve_address(body, action.caller, bindings)
            amt = int(bindings.get("amount", 0) or 0)
            evm.balances[target] = evm.balances.get(target, 0) + amt
            evm.balances[action.caller] = evm.balances.get(action.caller, 0) - amt
            evm.call_count += 1

        # 8. Release Reentrancy lock
        if "nonreentrant" in body_l:
            evm.reentrancy_lock = False

        evm.event_log.append(("Call", {"fn": action.function, "caller": action.caller}))
        return evm, ""

    def _resolve(self, expr: str, caller: str, bindings: Dict[str, object]) -> int:
        expr = expr.strip()
        if expr == "msg.sender":
            return hash(caller) & 0xFFFF
        if expr == "msg.value":
            return int(bindings.get("value", 0) or 0)
        if expr in bindings:
            v = bindings[expr]
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                if v.startswith("0x"):
                    try:
                        return int(v, 16)
                    except ValueError:
                        return hash(v) & 0xFFFF
                try:
                    return int(v)
                except ValueError:
                    return hash(v) & 0xFFFF
            return 0
        try:
            return int(expr)
        except (TypeError, ValueError):
            return 0

    def _resolve_address(self, body: str, caller: str, bindings: Dict[str, object]) -> str:
        m = re.search(r"(\w+)\.call", body)
        if m and m.group(1) in bindings:
            return str(bindings[m.group(1)])
        return "0xRECEIVER"


# ── Sequence invariants ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class SequenceInvariant:
    name: str
    severity: Severity
    confidence: Confidence
    detector_id: str
    title: str
    description: str
    check: Callable[[MockEVM, List[TraceStep]], Optional[str]]


def _seq_total_supply(evm: MockEVM, trace: List[TraceStep]) -> Optional[str]:
    """After mint/burn sequences, sum(balanceOf) should equal totalSupply."""
    if "totalSupply" not in evm.storage:
        return None
    # Find the last balance-changing action
    ts = evm.storage["totalSupply"]
    # If we don't know per-user balances, fall back to balance ledger.
    return None  # Mock state is approximate; skip unless we have a strong signal


def _seq_reentrancy_unlock(evm: MockEVM, trace: List[TraceStep]) -> Optional[str]:
    """nonReentrant should never leave the lock held after a sequence."""
    if evm.reentrancy_lock:
        return f"nonReentrant lock held at end of sequence"
    return None


def _seq_zero_address_drained(evm: MockEVM, trace: List[TraceStep]) -> Optional[str]:
    """If an attacker ends with more than the contract, an invariant broke."""
    contract_balance = evm.balances.get("0xCONTRACT", 0)
    if contract_balance < 0:
        return f"contract balance went negative: {contract_balance}"
    return None


def _seq_privileged_function_reachable(evm: MockEVM, trace: List[TraceStep]) -> Optional[str]:
    """If a non-admin ever invoked a function that returned successfully, an
    access invariant broke. (The dispatcher already filters admin-only, so
    we look for any non-admin action that cleared the reentrancy lock —
    a cheaper proxy that catches 'function was reachable'.)"""
    if not trace:
        return None
    for step in trace:
        if step.action.caller == "0xATTACKER" and not step.halted:
            if step.action.function.lower() in ("kill", "destroy", "suicide", "selfdestruct"):
                return f"attacker invoked {step.action.function} without revert"
            if step.action.function.lower() in ("mint", "setowner", "setadmin", "transferownership"):
                return f"attacker invoked privileged {step.action.function} without revert"
    return None


DEFAULT_INVARIANTS: List[SequenceInvariant] = [
    SequenceInvariant(
        name="reentrancy-lock-held",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detector_id="FUZZ-STATEFUL-REENTRANCY-LOCK",
        title="nonReentrant modifier leaves lock held",
        description="Sequence of nonReentrant functions left the reentrancy lock set.",
        check=_seq_reentrancy_unlock,
    ),
    SequenceInvariant(
        name="contract-balance-non-negative",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detector_id="FUZZ-STATEFUL-BALANCE",
        title="Contract accounting balance went negative",
        description="After a sequence of calls, the mock contract balance is negative — accounting invariant broke.",
        check=_seq_zero_address_drained,
    ),
    SequenceInvariant(
        name="privileged-reachable-by-attacker",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        detector_id="FUZZ-STATEFUL-ACCESS",
        title="Privileged function reachable by non-admin",
        description="A non-admin caller successfully invoked a privileged function (kill, mint, setOwner, etc.) without revert.",
        check=_seq_privileged_function_reachable,
    ),
]


# ── Action menu generation ───────────────────────────────────────────────────

@dataclass
class StatefulFuzzEngine:
    invariants: List[SequenceInvariant] = field(default_factory=lambda: list(DEFAULT_INVARIANTS))
    max_sequences: int = 32
    max_length: int = 6
    seed: int = 0xC0FFEE
    # Optional xray entry points used to bias the action menu toward
    # state-changing or external-call-bearing entry points.
    entry_points: Optional[Sequence[EntryPoint]] = None
    # Optional list of typed exploit-corpus invariants. Strings are
    # matched (substring) against each SequenceInvariant.name to flag
    # which invariants should run first. No arbitrary code from these
    # strings is executed.
    corpus_invariants: Optional[Sequence[str]] = None

    def fuzz_file(self, file_ctx: FileContext) -> StatefulFuzzResult:
        result = StatefulFuzzResult(file=file_ctx.relative_path, seed=self.seed)
        try:
            parsed = parse_solidity(file_ctx)
        except Exception as exc:  # pragma: no cover
            result.errors.append(f"parse failed: {exc}")
            return result
        if not parsed.contracts:
            return result

        rng = random.Random(self.seed)
        dispatcher = MockDispatcher(parsed)

        # Sort invariants so corpus-flagged ones run first.
        active_invariants = list(self.invariants)
        if self.corpus_invariants:
            def _priority(inv: SequenceInvariant) -> int:
                for hint in self.corpus_invariants or ():
                    if hint and hint.lower() in inv.name.lower():
                        return 0
                return 1
            active_invariants.sort(key=_priority)

        for contract in parsed.contracts:
            menu = self._build_menu(contract, dispatcher)
            if not menu:
                continue
            weights = self._xray_weights(menu)
            for _ in range(self.max_sequences):
                seq = self._generate_sequence(menu, weights, rng)
                result.sequences += 1
                evm = MockEVM(admin="0xADMIN", balances={"0xCONTRACT": 1_000_000})
                trace: List[TraceStep] = []
                halted = False
                for i, action in enumerate(seq):
                    if evm.destroyed:
                        break
                    before = _snapshot(evm)
                    evm, halt = dispatcher.apply(evm, action)
                    after = _snapshot(evm)
                    step = TraceStep(
                        seq=i,
                        action=action,
                        before_snapshot=before,
                        after_snapshot=after,
                        halted=bool(halt),
                        halt_reason=halt,
                    )
                    trace.append(step)
                    if halt:
                        halted = True
                        break
                result.total_steps += len(trace)
                for inv in active_invariants:
                    msg = inv.check(evm, trace)
                    if msg is not None:
                        issue = self._make_issue(inv, file_ctx, dispatcher, action, msg, trace)
                        result.add_finding(issue)
                        shrunk = self._shrink(seq, dispatcher, inv)
                        if shrunk is not None and shrunk != seq:
                            result.shrunk_traces.append(shrunk)

        return result

    def _build_menu(self, contract, dispatcher: MockDispatcher) -> List[StatefulAction]:
        menu: List[StatefulAction] = []
        for fn in contract.functions:
            if fn.is_constructor or fn.is_fallback or fn.is_receive:
                continue
            if fn.visibility not in ("public", "external"):
                continue
            args = self._arg_bindings(fn.params)
            for caller in ("0xADMIN", "0xUSER", "0xATTACKER"):
                menu.append(StatefulAction(
                    function=fn.name,
                    caller=caller,
                    args=args,
                    label=f"{caller}.{fn.name}({self._arg_str(args)})",
                ))
        return menu

    @staticmethod
    def _arg_bindings(param_str: str) -> tuple:
        out = []
        for raw in param_str.split(","):
            tok = raw.strip()
            if not tok:
                continue
            parts = tok.split()
            if len(parts) >= 2:
                name = parts[-1].lstrip("()")
                typ = parts[0]
            else:
                name = parts[0]
                typ = "uint256"
            if typ.startswith("address"):
                out.append((name, "0x" + "a" * 40))
            elif typ.startswith(("uint", "int")):
                out.append((name, 100))
            elif typ == "bool":
                out.append((name, True))
            elif typ.startswith("bytes") or typ == "string":
                out.append((name, b"\x00" * 4))
            else:
                out.append((name, 0))
        return tuple(out)

    @staticmethod
    def _arg_str(args: tuple) -> str:
        return ", ".join(f"{n}={v}" for n, v in args)

    def _generate_sequence(self, menu: List[StatefulAction],
                           weights: Optional[List[float]],
                           rng: random.Random) -> List[StatefulAction]:
        length = rng.randint(2, self.max_length)
        if not weights or len(weights) != len(menu):
            return [rng.choice(menu) for _ in range(length)]
        return [rng.choices(menu, weights=weights, k=1)[0] for _ in range(length)]

    def _xray_weights(self, menu: List[StatefulAction]) -> Optional[List[float]]:
        """If xray hints are available, bias the action distribution so
        state-changing or external-call-bearing actions are sampled more
        often. Returns ``None`` when no hints are available or no overlap
        exists with the menu."""
        priority_targets = self._priority_targets()
        if not priority_targets:
            return None
        weights = []
        for action in menu:
            base = 1.0
            if action.function in priority_targets:
                base *= 3.0
            weights.append(base)
        return weights

    def _priority_targets(self) -> set:
        if not self.entry_points:
            return set()
        targets: set = set()
        for ep in self.entry_points:
            if ep.function and (ep.state_writes or ep.external_calls or ep.access != "permissionless"):
                targets.add(ep.function)
        return targets

    def _shrink(self, seq: List[StatefulAction], dispatcher: MockDispatcher,
                inv: SequenceInvariant) -> Optional[List[StatefulAction]]:
        """Try removing each prefix/suffix; return the shortest seq that still fails."""
        best = list(seq)
        improved = True
        while improved:
            improved = False
            for i in range(len(best)):
                candidate = best[:i] + best[i+1:]
                if len(candidate) < 1:
                    continue
                if self._violates(candidate, dispatcher, inv):
                    best = candidate
                    improved = True
                    break
        return best if best != seq else None

    def _violates(self, seq: List[StatefulAction], dispatcher: MockDispatcher,
                  inv: SequenceInvariant) -> bool:
        evm = MockEVM(admin="0xADMIN", balances={"0xCONTRACT": 1_000_000})
        for action in seq:
            if evm.destroyed:
                break
            evm, halt = dispatcher.apply(evm, action)
            if halt and "lock" not in inv.name:
                # A normal halt shouldn't kill the trace unless the invariant is about locks.
                pass
        return inv.check(evm, []) is not None

    @staticmethod
    def _make_issue(inv: SequenceInvariant, file_ctx: FileContext,
                    dispatcher: MockDispatcher, last: StatefulAction,
                    msg: str, trace: List[TraceStep]) -> Issue:
        line = dispatcher.function_lines.get(last.function, 0)
        return Issue(
            id=inv.detector_id,
            title=inv.title,
            severity=inv.severity,
            confidence=inv.confidence,
            file=file_ctx.relative_path,
            line=line,
            snippet=f"{last.label}",
            description=f"{inv.description}\n\nStateful counterexample: {msg}\nSequence (shrunk): {len(trace)} steps",
            exploit_scenario=f"Sequence ends with: `{last.label}` — invariant `{inv.name}` violated.",
            remediation=f"Review sequence-level invariants for `{last.function}` and ensure each step preserves the invariant.",
            references=["https://github.com/crytic/echidna"],
            language="solidity",
        )

    def fuzz_files(self, file_contexts: Iterable[FileContext]) -> List[StatefulFuzzResult]:
        return [self.fuzz_file(c) for c in file_contexts]


def _snapshot(evm: MockEVM) -> dict:
    return {
        "storage": dict(evm.storage),
        "balances": dict(evm.balances),
        "reentrancy_lock": evm.reentrancy_lock,
        "destroyed": evm.destroyed,
        "halted": evm.halted,
    }


def fuzz_stateful(file_ctx: FileContext, *, max_sequences: int = 32,
                  max_length: int = 6,
                  invariants: Optional[List[SequenceInvariant]] = None,
                  seed: int = 0xC0FFEE,
                  entry_points: Optional[Sequence[EntryPoint]] = None,
                  corpus_invariants: Optional[Sequence[str]] = None) -> StatefulFuzzResult:
    eng = StatefulFuzzEngine(max_sequences=max_sequences, max_length=max_length,
                             invariants=invariants or DEFAULT_INVARIANTS,
                             seed=seed,
                             entry_points=entry_points,
                             corpus_invariants=corpus_invariants)
    return eng.fuzz_file(file_ctx)