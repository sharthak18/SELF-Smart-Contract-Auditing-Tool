"""Protocol-math invariants: what MUST hold, and whether the code enforces it.

SELF's deep pass names *sinks* (arbitrary sends, unchecked calls, delete on a
mapping of structs). This module is the other half of an expert review: the
accounting properties a protocol is supposed to preserve, and whether the
source actually asserts them anywhere.

Two rules keep this honest:

* A conversion formula is not an invariant. ``assets * totalSupply() /
  totalAssets()`` is how you price a share; it says nothing about whether
  shares stay backed. Only ``require`` / ``assert`` expressions count as
  enforced properties.
* Output is hypotheses, never proofs. ``propose_hypotheses`` emits Foundry
  handler sketches a reviewer can run; SELF cannot execute an EVM and does
  not claim these properties hold.

No catalog detectors, no new detector ids, no external scanner is wrapped.
"""

from __future__ import annotations

import re
from typing import Dict, Mapping, Optional, Sequence

from self_tool.autonomous.models import ExtractedContract, ExtractedFunction


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------

# Anything that reads a rate / share price rather than a raw balance.
RATE_READ_RE = re.compile(
    r"\bconvertToAssets\s*\(|\bconvertToShares\s*\(|\bgetPricePerFullShare\s*\(|"
    r"\bexchangeRate\s*\(|\bpricePerShare\b|\bstEthPerToken\b|\btokensPerStEth\b|"
    r"\bgetPooledEthByShares\s*\(|\binterestIndex\b|\bborrowIndex\b|\btotalBorrows\b|"
    r"\baccrualBlockNumber\b|\blastAccrual\b|\brate\s*\(\s*\)",
    re.IGNORECASE,
)
# Interest / index settlement. Calling any of these counts as "accrued".
ACCRUE_RE = re.compile(
    r"\baccrue\w*\s*\(|\b_update(?:Interest|Index|Rate|ExchangeRate|Accrual)\w*\s*\(|"
    r"\bupdate(?:Interest|Index|Rate|ExchangeRate|Accrual)\w*\s*\(|"
    r"\b_sync\s*\(|\bsync\s*\(|\bharvest\s*\(|\brefresh\w*\s*\(|"
    r"\b_setExchangeRate\s*\(|\b_setRate\s*\(|\baccrueInterest\s*\(",
    re.IGNORECASE,
)
# Entry points that move value and therefore must price against fresh state.
VALUE_PATH_RE = re.compile(
    r"^(deposit|mint|withdraw|redeem|borrow|repay|liquidate|seize|rebalance|"
    r"harvest|stake|unstake|claim|requestDeposit|requestRedeem|flashLoan)\w*$",
    re.IGNORECASE,
)
SHARE_SIDE_RE = re.compile(
    r"\btotalSupply\s*\(|\bshares\b|\bShares\b|\bbalanceOf\s*\(",
)
ASSET_SIDE_RE = re.compile(
    r"\btotalAssets\b|\bgetTotalAssets\b|\basset\.balanceOf\s*\(|"
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)|\btotalReserves\b|\btotalCollateral\b",
)
# Guarded properties are only real inside require / assert / revert-if-not.
ENFORCED_RE = re.compile(r"\b(?:require|assert|assert!)\s*\((.+?)\)\s*;", re.DOTALL)
# Constant-product / concentrated-liquidity reserve state.
RESERVE_RE = re.compile(
    r"\breserve0\b|\breserve1\b|\b_reserves\b|\bgetReserves\s*\(|\breserves\s*\[|"
    r"\bsqrtPriceX96\b|\bsqrtP\b|\bliquidityNet\b",
)
AMM_OP_RE = re.compile(r"^(swap|mint|burn|addLiquidity|removeLiquidity|exchange)\w*$", re.IGNORECASE)
# A real k check compares the live product against the stored product.
K_CHECK_RE = re.compile(
    r"(?:require|assert)\s*\([^;]{0,400}\*[^;]{0,400}>=[^;]{0,400}\*",
    re.DOTALL,
)
K_UPDATE_HOOK_RE = re.compile(r"\b_?update\s*\(", re.IGNORECASE)
BORROW_LIQ_RE = re.compile(
    r"^(borrow|liquidate\w*|seize\w*|withdraw\w*|repay\w*|flashLoan)$",
    re.IGNORECASE,
)
HEALTH_CALL_RE = re.compile(
    r"\bhealthFactor\b|\bgetHealthFactor\b|\bcheckHealth\b|\baccountHealth\b|"
    r"\brequireHealthy\b|\bisHealthy\b|\bcheckAccountStatus\b|\b_getAccountLiquidity\b|"
    r"\bgetAccountLiquidity\b|\bcheckLiquidity\b|\b_ensureSolvency\b|\bassertSolvent\b",
    re.IGNORECASE,
)
TSTORE_WRITE_RE = re.compile(r"\btstore\s*\(|\bTSTORE\b")
# Transient data only becomes poison when the storage it refers to is removed
# underneath it. A bare tstore that is overwritten or expires with the
# transaction is normal EIP-1153 usage and must NOT be reported.
TRANSIENT_KILLER_RE = re.compile(r"\bdelete\s+\w+|\.\s*pop\s*\(\s*\)")
SHARE_MATH_RE = re.compile(
    r"\bconvertToShares\b|\bconvertToAssets\b|\btotalAssets\b|\bpreviewDeposit\b|"
    r"\bpricePerShare\b|\bgetPricePerFullShare\b",
    re.IGNORECASE,
)
LST_RATE_RE = re.compile(
    r"\bstEthPerToken\b|\btokensPerStEth\b|\bgetPooledEthByShares\b|\bgetExchangeRate\b",
)
SIG_RE = re.compile(
    r"\becrecover\b|\bECDSA\.recover\b|\bpermit\s*\(|\bisValidSignature\b|"
    r"\bverifySignature\b|\bvalidateUserOp\b",
    re.IGNORECASE,
)
TSTORE_RE = re.compile(r"\btstore\b|\btload\b|\bTSTORE\b|\bTLOAD\b")
CALLBACK_RE = re.compile(
    r"\bonFlashLoan\b|\bonFlashloan\b|\bexecuteOperation\b|\buniswapV2Call\b|"
    r"\buniswapV3SwapCallback\b|\bpancakeCall\b|\breceiveFlashLoan\b|\bunlockCallback\b",
    re.IGNORECASE,
)
INTERNAL_CALL_RE = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*\(")
_SKIP_FUNCS = {"constructor", "receive", "fallback", "__default__", "__init__"}


# --------------------------------------------------------------------------
# Facts
# --------------------------------------------------------------------------

def invariant_facts(
    contracts: Sequence[ExtractedContract],
    combined: str,
    types: Sequence[str] = (),
) -> Dict[str, bool]:
    """Protocol-math facts: accounting properties the code fails to enforce."""
    functions = [func for contract in contracts for func in contract.functions]
    public = [
        func for func in functions
        if _is_public(func) and func.name.lower() not in _SKIP_FUNCS
    ]
    helpers = _helpers_by_contract(contracts)
    type_set = {str(item).lower() for item in types}

    return {
        "missing_accrue_on_value_path": _missing_accrue(public, helpers),
        "missing_share_invariant": _missing_share_invariant(combined, type_set, contracts),
        "missing_k_invariant": _missing_k_invariant(combined, functions, type_set),
        "missing_health_check": _missing_health_check(public, functions, combined, type_set),
        "tstore_delete_poison": _tstore_delete_poison(functions),
    }


def _is_public(func: ExtractedFunction) -> bool:
    return func.visibility in {"public", "external", "default", ""} or func.language in {
        "rust", "move", "cairo", "sway", "tact", "huff",
    }


def _helpers_by_contract(
    contracts: Sequence[ExtractedContract],
) -> Dict[int, Dict[str, ExtractedFunction]]:
    """Internal helpers grouped by the contract instance that owns them."""
    out: Dict[int, Dict[str, ExtractedFunction]] = {}
    for contract in contracts:
        table: Dict[str, ExtractedFunction] = {}
        for func in contract.functions:
            table.setdefault(func.name, func)
        out[id(contract)] = table
    return out


def _missing_accrue(
    public: Sequence[ExtractedFunction],
    helpers: Mapping[int, Dict[str, ExtractedFunction]],
) -> bool:
    """A value-moving entry point prices against a rate it never refreshes."""
    table = _flatten(helpers)
    for func in public:
        if not VALUE_PATH_RE.match(func.name or ""):
            continue
        body = func.body or ""
        if not RATE_READ_RE.search(body):
            continue
        if _accrues(func, table):
            continue
        return True
    return False


def _accrues(func: ExtractedFunction, table: Mapping[str, ExtractedFunction]) -> bool:
    body = func.body or ""
    if ACCRUE_RE.search(body):
        return True
    # One level of indirection: `deposit()` -> `_updateIndex()` still accrues.
    for name in INTERNAL_CALL_RE.findall(body):
        helper = table.get(name)
        if helper is None or helper is func:
            continue
        if ACCRUE_RE.search(helper.body or ""):
            return True
    return False


def _flatten(helpers: Mapping[int, Dict[str, ExtractedFunction]]) -> Dict[str, ExtractedFunction]:
    flat: Dict[str, ExtractedFunction] = {}
    for table in helpers.values():
        for name, func in table.items():
            flat.setdefault(name, func)
    return flat


def _missing_share_invariant(
    combined: str,
    types: Sequence[str],
    contracts: Sequence[ExtractedContract],
) -> bool:
    """Share math exists but nothing asserts that shares stay backed.

    A conversion formula such as ``assets * totalSupply() / totalAssets()`` is
    deliberately *not* evidence here: it prices a share, it does not constrain
    one. Only a ``require`` / ``assert`` relating a share quantity to an asset
    quantity counts.
    """
    if not SHARE_MATH_RE.search(combined):
        return False
    vault_like = bool({"vault", "staking", "lending", "derivative", "lst"} & set(types)) or any(
        contract.role_guess in {"vault", "staking"} for contract in contracts
    )
    if not vault_like and not re.search(r"\bERC4626\b|\bERC20Votes\b", combined):
        return False
    return not _enforced_share_property(combined)


def _enforced_share_property(combined: str) -> bool:
    for match in ENFORCED_RE.finditer(combined):
        expr = match.group(1)
        if SHARE_SIDE_RE.search(expr) and ASSET_SIDE_RE.search(expr):
            return True
    return False


def _missing_k_invariant(
    combined: str,
    functions: Sequence[ExtractedFunction],
    types: Sequence[str],
) -> bool:
    """Constant-product reserves are mutated with no non-decreasing k check."""
    if not RESERVE_RE.search(combined):
        return False
    amm_like = "amm" in set(types) or "pool" in set(types) or bool(re.search(
        r"\bfunction\s+swap\b|\bfunction\s+exchange\b|\bexactInput\w*\s*\(", combined
    ))
    if not amm_like:
        return False
    mutates_reserves = any(
        AMM_OP_RE.match(func.name or "") for func in functions if _is_public(func)
    )
    if not mutates_reserves:
        return False
    if K_CHECK_RE.search(combined):
        return False
    # A Uniswap-style `_update` re-reads balances, which is the k check.
    if K_UPDATE_HOOK_RE.search(combined):
        return False
    return True


def _missing_health_check(
    public: Sequence[ExtractedFunction],
    functions: Sequence[ExtractedFunction],
    combined: str,
    types: Sequence[str],
) -> bool:
    """Collateral/debt moves without a solvency check on that path."""
    lending = "lending" in set(types) or bool(re.search(
        r"\bfunction\s+(borrow|liquidate)\w*\s*\(", combined, re.IGNORECASE
    ))
    if not lending:
        return False
    exposed = [func for func in public if BORROW_LIQ_RE.match(func.name or "")]
    if not exposed:
        return False
    for func in exposed:
        if not HEALTH_CALL_RE.search(func.body or ""):
            return True
    return False


def _tstore_delete_poison(functions: Sequence[ExtractedFunction]) -> bool:
    """Transient state outliving a ``delete`` / ``.pop()`` in the same function.

    EIP-1153 transient slots survive to the end of the transaction. If the
    storage entry a slot describes is deleted or popped while the slot is still
    set, a later call in the same transaction reads a transient value that no
    longer corresponds to anything. A bare ``tstore`` with no delete is normal
    usage and must not be flagged.
    """
    for func in functions:
        body = func.body or ""
        if not TSTORE_WRITE_RE.search(body):
            continue
        if TRANSIENT_KILLER_RE.search(body):
            return True
    return False


# --------------------------------------------------------------------------
# Hypotheses (Foundry sketches — not proofs)
# --------------------------------------------------------------------------

_HYPOTHESES = (
    (
        "INV-SHARE-BACKING",
        lambda facts, types, combined: bool(
            facts.get("is_share_vault") or SHARE_MATH_RE.search(combined)
        ),
        "invariant_shareBacking()",
        "after every call: assertLe(asset.convertToAssets(asset.totalSupply()), asset.totalAssets())",
    ),
    (
        "INV-EMPTY-VAULT",
        lambda facts, types, combined: bool(
            facts.get("is_share_vault") or facts.get("missing_virtual_shares")
        ),
        "invariant_emptyVaultFirstDeposit()",
        "when totalSupply() == 0, a first deposit must mint > 0 shares and a direct "
        "token donation must not make the next depositor mint 0",
    ),
    (
        "INV-K",
        lambda facts, types, combined: bool(
            "amm" in types or RESERVE_RE.search(combined)
        ),
        "invariant_constantProduct()",
        "after swap/mint/burn: assertGe(balance0 * balance1, reserve0 * reserve1) "
        "accounting for the fee",
    ),
    (
        "INV-ACCRUE-FIRST",
        lambda facts, types, combined: bool(
            facts.get("missing_accrue_on_value_path")
            or facts.get("uses_lst_exchange_rate")
            or facts.get("is_share_vault")
            or RATE_READ_RE.search(combined)
            or LST_RATE_RE.search(combined)
        ),
        "invariant_accrueBeforePricing()",
        "no deposit/withdraw/liquidate may read a share price before interest is "
        "accrued; fuzz the accrual timestamp forward and assert monotonic rates",
    ),
    (
        "INV-HEALTH",
        lambda facts, types, combined: bool(
            facts.get("is_lending") or "lending" in types
            or BORROW_LIQ_RE.search(combined)
        ),
        "invariant_solvencyAfterBorrow()",
        "after borrow/liquidate/withdraw: assertGt(healthFactor(account), 1e18) "
        "or the account is liquidated in the same call",
    ),
    (
        "INV-VIEW-LOCK",
        lambda facts, types, combined: bool(
            facts.get("has_view_price") or facts.get("has_flashloan_callback")
            or facts.get("value_depends_on_price") or CALLBACK_RE.search(combined)
        ),
        "invariant_viewStableDuringMutation()",
        "a view price read from a re-entrant callback must equal the price before "
        "and after the mutating call (Curve read-only reentrancy)",
    ),
    (
        "INV-TSTORE-CLEAR",
        lambda facts, types, combined: bool(
            facts.get("uses_transient_storage") or TSTORE_RE.search(combined)
        ),
        "invariant_transientCleared()",
        "every transient slot written by a call reads as zero before the call "
        "returns and before any external call leaves the contract",
    ),
    (
        "INV-SIG-BIND",
        lambda facts, types, combined: bool(
            facts.get("has_signature_auth") or SIG_RE.search(combined)
        ),
        "invariant_signatureBound()",
        "the signed digest binds chainId, verifyingContract and a strictly "
        "increasing nonce; replay across chain, contract and nonce must revert",
    ),
)


def propose_hypotheses(
    facts: Optional[Mapping[str, bool]] = None,
    types: Sequence[str] = (),
    combined: str = "",
) -> Sequence[str]:
    """Return targeted Foundry invariant sketches for this protocol.

    Each entry names the property and the handler a reviewer would write. They
    are hypotheses to falsify, not properties SELF has proven.
    """
    fact_map = dict(facts or {})
    type_set = {str(item).lower() for item in types}
    out = []
    for inv_id, applies, handler, sketch in _HYPOTHESES:
        try:
            relevant = bool(applies(fact_map, type_set, combined))
        except Exception:
            relevant = False
        if not relevant:
            continue
        out.append(f"{inv_id}: {handler} — {sketch}")
    return out


def hypothesis_ids(hypotheses: Sequence[str]) -> Sequence[str]:
    """The INV-* identifiers inside rendered hypotheses."""
    return [item.split(":", 1)[0].strip() for item in hypotheses if ":" in item]


def notes_for_facts(facts: Mapping[str, bool]) -> Sequence[str]:
    """Architecture notes for the invariant facts that fired."""
    notes = []
    if facts.get("missing_accrue_on_value_path"):
        notes.append(
            "A value-moving entry point reads a share price / interest index without "
            "accruing first — stale-rate accounting is in scope."
        )
    if facts.get("missing_share_invariant"):
        notes.append(
            "Share math is present but no require/assert ties totalSupply to "
            "totalAssets — share backing is an unenforced invariant."
        )
    if facts.get("missing_k_invariant"):
        notes.append(
            "Constant-product reserves are mutated with no non-decreasing k check "
            "and no Uniswap-style _update hook."
        )
    if facts.get("missing_health_check"):
        notes.append(
            "A borrow/liquidate/withdraw path moves collateral or debt without a "
            "health / liquidity check on that path."
        )
    if facts.get("tstore_delete_poison"):
        notes.append(
            "A function writes transient storage and also delete/pop-s the storage it "
            "describes — the transient slot can outlive its entry for the rest of the tx."
        )
    return notes
