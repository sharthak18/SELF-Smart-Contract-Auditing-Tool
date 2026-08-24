"""Build a protocol-level understanding of an ingested project."""

from __future__ import annotations

import re
from typing import Dict, List, Sequence, Set

from self_tool.autonomous.brain import load_business_logic, load_math_models
from self_tool.autonomous.ingest import ProjectIngestion, all_file_contexts
from self_tool.autonomous.languages import extract_contracts
from self_tool.autonomous.models import (
    ExtractedContract,
    ExtractedFunction,
    ProtocolUnderstanding,
    TokenFlow,
)
from self_tool.core.protocol_context import ProtocolContext


PRIVILEGED_MODIFIERS = {
    "onlyowner", "onlyadmin", "onlyrole", "onlygovernance", "onlykeeper",
    "requiresauth", "restricted",
}
GUARD_MODIFIERS = {"nonreentrant", "whennotpaused", "whenpaused", "initializer"}
AUTH_BODY_RE = re.compile(
    r"(msg\.sender\s*==|require\s*\(\s*msg\.sender|onlyOwner|hasRole|"
    r"get_caller_address|msg_sender\s*\(|sender\s*\(\s*\)\s*==|"
    r"assert!\s*\(\s*signer|Signer<)",
    re.IGNORECASE,
)
ORACLE_RE = re.compile(
    r"getReserves|slot0\s*\(|latestRoundData|consult\s*\(|observe\s*\(|"
    r"getAmountOut|getAmountsOut|balanceOf\s*\(\s*address\s*\(\s*this",
    re.IGNORECASE,
)
SHARE_RE = re.compile(
    r"convertToShares|convertToAssets|totalAssets|previewDeposit|"
    r"totalSupply|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
    re.IGNORECASE,
)
FLASH_RE = re.compile(
    r"onFlashLoan|onFlashloan|executeOperation|uniswapV2Call|uniswapV3SwapCallback|"
    r"pancakeCall|receiveFlashLoan|unlockCallback",
    re.IGNORECASE,
)
DONATE_RE = re.compile(r"function\s+donate\w*|donateToReserves|donateTo\s*\(", re.IGNORECASE)
HEALTH_RE = re.compile(
    r"healthFactor|accountHealth|checkAccountStatus|requireHealthy|isHealthy|liquidity\s*>",
    re.IGNORECASE,
)
MARKET_REG_RE = re.compile(
    r"function\s+(registerMarket|addMarket|createMarket|newMarket)\b",
    re.IGNORECASE,
)
CLAMM_RE = re.compile(
    r"currentTick|sqrtPriceX96|sqrtP\b|TickMath|getSqrtRatioAtTick|liquidityNet",
    re.IGNORECASE,
)
LST_RATE_RE = re.compile(
    r"stEthPerToken|tokensPerStEth|getPooledEthByShares|getExchangeRate",
    re.IGNORECASE,
)
HOOK_RE = re.compile(
    r"beforeSwap|afterSwap|beforeAddLiquidity|afterAddLiquidity|IHooks|unlockCallback",
    re.IGNORECASE,
)
PERMIT2_RE = re.compile(r"\bPermit2\b|IAllowanceTransfer|permitWitnessTransferFrom")
ASYNC_VAULT_RE = re.compile(
    r"requestDeposit|requestRedeem|ERC7540|pendingDepositRequest",
    re.IGNORECASE,
)
REWARD_DELTA_RE = re.compile(
    r"balanceOf[\s\S]{0,280}(?:redeemRewards|claimRewards|batchHarvest)|"
    r"(?:redeemRewards|claimRewards|batchHarvest)[\s\S]{0,280}balanceOf",
    re.IGNORECASE,
)
CALLBACK_AUTH_RE = re.compile(
    r"msg\.sender\s*==|require\s*\(\s*msg\.sender|initiator\s*==|onlyPool|onlyVault",
    re.IGNORECASE,
)
SIG_RE = re.compile(r"ecrecover|ECDSA\.recover|permit\s*\(|isValidSignature", re.IGNORECASE)
SLIPPAGE_RE = re.compile(r"minAmountOut|amountOutMin|min_dy|min_lp|deadline|maxAmountIn", re.IGNORECASE)
VIRTUAL_SHARES_RE = re.compile(r"_decimalsOffset|virtualShares|DEAD_SHARES|MINIMUM_LIQUIDITY|10\*\*3", re.IGNORECASE)
DIV_MUL_RE = re.compile(r"/\s*[A-Za-z_][\w.]*\s*\*")
LOOP_RE = re.compile(r"for\s*\([^;]*;\s*[^;]*\.length|for\s+\w+\s+in\s+range\s*\(", re.IGNORECASE)
CREATE2_RE = re.compile(r"\bcreate2\b|CREATE2", re.IGNORECASE)
TSTORE_RE = re.compile(r"\btstore\b|\btload\b|\bTSTORE\b|\bTLOAD\b")
SELFDESTRUCT_RE = re.compile(r"selfdestruct|self\.destruct|SELFDESTRUCT", re.IGNORECASE)
TXORIGIN_RE = re.compile(r"tx\.origin")
RANDOM_RE = re.compile(r"block\.(timestamp|number|prevrandao|difficulty)|blockhash\s*\(")
VYPER_VERSION_RE = re.compile(r"#\s*@version\s+([\d.]+)")
INIT_RE = re.compile(r"\bfunction\s+initialize\b|\binitializer\b")
DISABLE_INIT_RE = re.compile(r"_disableInitializers|initialized\s*=\s*true")
BALANCE_TRUST_RE = re.compile(r"address\s*\(\s*this\s*\)\s*\.balance")
NULLIFIER_RE = re.compile(r"processedMessages|usedNullifier|nullify|alreadyProcessed|messageHash", re.IGNORECASE)
CHECKPOINT_RE = re.compile(r"getPastVotes|checkpoints|getPriorVotes", re.IGNORECASE)


def understand(
    ingestion: ProjectIngestion,
    protocol_ctx: ProtocolContext,
) -> ProtocolUnderstanding:
    files = all_file_contexts(ingestion)
    contracts = extract_contracts(files)
    combined = ingestion.combined_source
    types = _protocol_types(protocol_ctx, combined, contracts)
    facts = _facts(ingestion, protocol_ctx, contracts, types, combined)
    flows = _token_flows(contracts)
    privileged, permissionless = _surfaces(contracts)
    invariants = _invariants(contracts)
    formulas = _math_formulas(combined, types)
    deps = _external_deps(ingestion, combined)
    notes = _architecture_notes(protocol_ctx, contracts, types, facts)
    summary = _summary(protocol_ctx, types, contracts, facts)
    return ProtocolUnderstanding(
        name=protocol_ctx.protocol_name or "Unknown Protocol",
        types=types,
        summary=summary,
        languages=list(ingestion.languages),
        contracts=contracts,
        facts=facts,
        token_flows=flows,
        invariants=invariants,
        math_formulas=formulas,
        privileged_ops=privileged,
        permissionless_ops=permissionless,
        external_deps=deps,
        architecture_notes=notes,
        source_chars=len(combined),
        file_count=len(files),
    )


def _protocol_types(
    ctx: ProtocolContext,
    combined: str,
    contracts: Sequence[ExtractedContract],
) -> List[str]:
    scores: Dict[str, int] = {}
    blob = " ".join([
        ctx.protocol_type, ctx.protocol_name, ctx.description,
        ctx.readme_content, combined[:20000],
        " ".join(c.name for c in contracts),
        " ".join(c.role_guess for c in contracts),
    ]).lower()
    catalog = load_business_logic()
    for proto_id, spec in catalog.items():
        score = 0
        if ctx.protocol_type == proto_id:
            score += 4
        for verb in spec.get("entry_verbs") or []:
            if re.search(rf"\b{re.escape(verb.lower())}\b", blob):
                score += 1
        if proto_id in blob:
            score += 2
        if any(c.role_guess in {proto_id, "pool" if proto_id == "amm" else proto_id} for c in contracts):
            score += 2
        scores[proto_id] = score
    ranked = [key for key, value in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0])) if value >= 2]
    if not ranked and ctx.protocol_type and ctx.protocol_type != "unknown":
        ranked = [ctx.protocol_type]
    if not ranked:
        ranked = ["unknown"]
    return ranked[:4]


def _is_auth(func: ExtractedFunction) -> bool:
    mods = {item.lower() for item in func.modifiers}
    if mods & PRIVILEGED_MODIFIERS:
        return True
    if AUTH_BODY_RE.search(func.body) or AUTH_BODY_RE.search(func.params):
        return True
    return False


def _is_public(func: ExtractedFunction) -> bool:
    return func.visibility in {"public", "external", "default", ""} or func.language in {
        "rust", "move", "cairo", "sway", "tact", "huff",
    }


def _facts(
    ingestion: ProjectIngestion,
    ctx: ProtocolContext,
    contracts: Sequence[ExtractedContract],
    types: Sequence[str],
    combined: str,
) -> Dict[str, bool]:
    functions = [func for contract in contracts for func in contract.functions]
    public_fns = [func for func in functions if _is_public(func)]
    value_out = any(
        func.mutability == "payable"
        or "call" in func.external_calls
        or "transfer" in func.external_calls
        or "send" in func.external_calls
        or "raw_call" in func.external_calls
        for func in public_fns
        if not _is_auth(func)
    )
    ext_before_write = any(_external_call_before_write(func) for func in public_fns)
    uses_spot = bool(ORACLE_RE.search(combined)) and not (
        ctx.uses_twap or ctx.uses_chainlink or "observe(" in combined or "consult(" in combined
    )
    value_depends_price = any(key in types for key in ("lending", "vault", "derivative", "amm"))
    share_vault = bool(SHARE_RE.search(combined)) and any(
        key in types or any(c.role_guess in {"vault", "staking"} for c in contracts)
        for key in ("vault", "staking", "lending")
    )
    missing_virtual = share_vault and not VIRTUAL_SHARES_RE.search(combined)
    unguarded = any(
        func.is_privileged_name and _is_public(func) and not _is_auth(func)
        and func.name.lower() not in {"receive", "fallback", "__default__", "__init__"}
        for func in functions
    )
    vyper_bad = False
    for match in VYPER_VERSION_RE.finditer(combined):
        if _vyper_vulnerable(match.group(1)):
            vyper_bad = True
    facts = {
        "permissionless_value_out": value_out,
        "external_call_before_write": ext_before_write,
        "has_view_price": bool(re.search(
            r"get_virtual_price|convertToAssets|getPricePerFullShare|getReserves",
            combined,
        )),
        "uses_spot_price": uses_spot,
        "value_depends_on_price": value_depends_price,
        "has_flashloan_callback": bool(FLASH_RE.search(combined)),
        "is_share_vault": share_vault,
        "missing_virtual_shares": missing_virtual,
        "div_before_mul": bool(DIV_MUL_RE.search(combined)),
        "unguarded_privileged_write": unguarded,
        "uses_tx_origin_auth": bool(TXORIGIN_RE.search(combined) and re.search(
            r"tx\.origin\s*==|require\s*\(\s*tx\.origin", combined
        )),
        "has_signature_auth": bool(SIG_RE.search(combined)),
        "missing_signature_binding": bool(SIG_RE.search(combined)) and not re.search(
            r"nonces|chainid|CHAINID|EIP712|domainSeparator", combined, re.IGNORECASE
        ),
        "is_upgradeable": bool(ctx.is_upgradeable or re.search(
            r"UUPSUpgradeable|TransparentUpgradeableProxy|upgradeTo|delegatecall",
            combined,
        )),
        "initializer_unprotected": bool(INIT_RE.search(combined)) and not bool(DISABLE_INIT_RE.search(combined)),
        "value_changing_amm_op": any(t in types for t in ("amm",)) or bool(re.search(
            r"\bfunction\s+swap\b|\bfunction\s+exchange\b", combined
        )),
        "missing_slippage": bool(re.search(r"\b(swap|exchange|addLiquidity)\b", combined, re.IGNORECASE))
            and not bool(SLIPPAGE_RE.search(combined)),
        "is_governance": "governance" in types,
        "votes_not_checkpointed": "governance" in types and not bool(CHECKPOINT_RE.search(combined)),
        "is_bridge": "bridge" in types,
        "missing_message_nullifier": "bridge" in types and not bool(NULLIFIER_RE.search(combined)),
        "has_selfdestruct": bool(SELFDESTRUCT_RE.search(combined)),
        "solana_missing_signer_or_cpi": _solana_auth_gap(contracts, combined),
        "solana_alias_or_sysvar_risk": "rust" in ingestion.languages and bool(re.search(
            r"AccountInfo|UncheckedAccount|Sysvar", combined
        )),
        "move_unauth_write": _move_unauth(contracts),
        "vyper_vulnerable_compiler": vyper_bad,
        "unbounded_loop_over_storage": bool(LOOP_RE.search(combined)),
        "uses_weak_randomness": bool(RANDOM_RE.search(combined)) and bool(re.search(
            r"random|lottery|raffle|winner|rarity", combined, re.IGNORECASE
        )),
        "credits_transfer_amount_not_delta": bool(re.search(r"transferFrom", combined))
            and not bool(re.search(r"balanceOf\s*\([^)]+\)\s*;", combined)),
        "uses_create2": bool(CREATE2_RE.search(combined)),
        "uses_chainlink_like": bool(ctx.uses_chainlink or re.search(r"latestRoundData|AggregatorV3", combined)),
        "missing_sequencer_check": bool(ctx.uses_chainlink or re.search(r"latestRoundData", combined))
            and not bool(re.search(r"sequencer", combined, re.IGNORECASE)),
        "is_lending": "lending" in types,
        "liquidation_unrestricted": "lending" in types and bool(re.search(r"liquidate", combined, re.IGNORECASE)),
        "is_huff": "huff" in ingestion.languages,
        "cairo_unauth_write": _lang_unauth(contracts, "cairo", r"get_caller_address"),
        "sway_unauth_write": _lang_unauth(contracts, "sway", r"msg_sender"),
        "tact_unauth_receive": _lang_unauth(contracts, "tact", r"sender\s*\("),
        "uses_transient_storage": bool(TSTORE_RE.search(combined)),
        "is_account_abstraction": bool(re.search(r"validateUserOp|EntryPoint", combined)),
        "trusts_raw_balance": bool(BALANCE_TRUST_RE.search(combined)),
        "uses_docs_multisig": bool(ctx.uses_multisig),
        "uses_docs_timelock": bool(ctx.uses_timelock),
        "uses_docs_reentrancy_guard": bool(ctx.uses_reentrancy_guard),
        "donation_skips_health": _donation_skips_health(combined, types),
        "permissionless_market_register": _permissionless_market(combined, functions),
        "unauthenticated_callback": _unauthenticated_callback(functions, combined),
        "concentrated_liquidity": bool(CLAMM_RE.search(combined)),
        "clamm_tick_equality_risk": bool(re.search(
            r"\bsqrtP\b|nextSqrtP|baseL|nearestCurrentTick", combined
        )),
        "uses_lst_exchange_rate": bool(LST_RATE_RE.search(combined)),
        "has_hooks": bool(HOOK_RE.search(combined)),
        "uses_permit2": bool(PERMIT2_RE.search(combined)),
        "is_async_vault": bool(ASYNC_VAULT_RE.search(combined)),
        "reward_measured_as_balance_delta": bool(REWARD_DELTA_RE.search(combined)),
        "sui_object_or_oracle": "move" in ingestion.languages and bool(re.search(
            r"oracle|spot|price|exchange_rate", combined, re.IGNORECASE
        )),
    }
    return facts


def _donation_skips_health(combined: str, types: Sequence[str]) -> bool:
    if not DONATE_RE.search(combined):
        return False
    if "lending" not in types and not re.search(r"\b(borrow|liquidate|eToken|dToken)\b", combined, re.I):
        return False
    return not bool(HEALTH_RE.search(combined))


def _permissionless_market(combined: str, functions: Sequence[ExtractedFunction]) -> bool:
    if not MARKET_REG_RE.search(combined):
        return False
    if re.search(r"allowlist|whitelist|approvedMarket|onlyGovernor", combined, re.IGNORECASE):
        return False
    for func in functions:
        if re.search(r"registerMarket|addMarket|createMarket|newMarket", func.name, re.I):
            if _is_public(func) and not _is_auth(func):
                return True
    return bool(MARKET_REG_RE.search(combined))


def _unauthenticated_callback(functions: Sequence[ExtractedFunction], combined: str) -> bool:
    if not FLASH_RE.search(combined):
        return False
    for func in functions:
        if not FLASH_RE.search(func.name) and not FLASH_RE.search(func.body[:80]):
            continue
        if CALLBACK_AUTH_RE.search(func.body) or _is_auth(func):
            continue
        return True
    return not bool(CALLBACK_AUTH_RE.search(combined))


def _external_call_before_write(func: ExtractedFunction) -> bool:
    if not func.body or not func.state_writes:
        return False
    call = re.search(
        r"\.(?:call|delegatecall|transfer|send|transferFrom|safeTransfer)\s*(?:\{|\()|raw_call\s*\(|invoke(?:_signed)?\s*\(",
        func.body,
    )
    if not call:
        return False
    after = func.body[call.start():]
    return any(
        re.search(rf"\b{re.escape(name)}\b(?:\s*\[[^\]]+\])*\s*(?:=|\+=|-=)", after)
        for name in func.state_writes
    )


def _vyper_vulnerable(version: str) -> bool:
    parts = [int(p) for p in version.split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts
    if (major, minor) == (0, 2) and patch >= 15:
        return True
    if (major, minor) == (0, 3) and patch == 0:
        return True
    if (major, minor, patch) == (0, 3, 7):
        return True
    return False


def _solana_auth_gap(contracts: Sequence[ExtractedContract], combined: str) -> bool:
    if "rust" not in {c.language for c in contracts}:
        return False
    if re.search(r"AccountInfo|UncheckedAccount", combined) and not re.search(r"Signer<", combined):
        return True
    if re.search(r"\binvoke\s*\(", combined) and not re.search(r"program::|Program<", combined):
        return True
    return False


def _move_unauth(contracts: Sequence[ExtractedContract]) -> bool:
    for contract in contracts:
        if contract.language != "move":
            continue
        for func in contract.functions:
            if "entry" in func.params or func.visibility == "public":
                if re.search(r"borrow_global_mut|move_from|move_to", func.body) and "signer" not in func.body:
                    return True
    return False


def _lang_unauth(contracts: Sequence[ExtractedContract], language: str, auth_pat: str) -> bool:
    for contract in contracts:
        if contract.language != language:
            continue
        for func in contract.functions:
            if func.is_privileged_name or re.search(r"write|owner|mint|upgrade", func.body, re.IGNORECASE):
                if not re.search(auth_pat, func.body):
                    return True
    return False


def _token_flows(contracts: Sequence[ExtractedContract]) -> List[TokenFlow]:
    flows: List[TokenFlow] = []
    for contract in contracts:
        for func in contract.functions:
            if not _is_public(func):
                continue
            outgoing = any(call in func.external_calls for call in (
                "call", "transfer", "send", "safeTransfer", "raw_call",
            ))
            incoming = func.mutability == "payable" or "transferFrom" in func.external_calls
            if incoming:
                flows.append(TokenFlow("in", f"{contract.name}.{func.name}", func.file, func.line, func.mutability or "transferFrom"))
            if outgoing:
                flows.append(TokenFlow("out", f"{contract.name}.{func.name}", func.file, func.line, ",".join(func.external_calls)))
    return flows


def _surfaces(contracts: Sequence[ExtractedContract]) -> tuple:
    privileged: List[str] = []
    permissionless: List[str] = []
    for contract in contracts:
        for func in contract.functions:
            if not _is_public(func) or func.name in {"receive", "fallback", "__default__"}:
                continue
            label = f"{contract.name}.{func.name}() @ {func.file}:{func.line}"
            if _is_auth(func) or func.is_privileged_name:
                privileged.append(label)
            else:
                permissionless.append(label)
    return privileged[:40], permissionless[:40]


def _invariants(contracts: Sequence[ExtractedContract]) -> List[str]:
    found: List[str] = []
    guard = re.compile(r"(?:require|assert|assert!)\s*\((.+?)\)\s*;?", re.DOTALL)
    for contract in contracts:
        for func in contract.functions:
            for match in guard.finditer(func.body):
                expr = " ".join(match.group(1).split())
                if len(expr) > 160:
                    expr = expr[:157] + "..."
                found.append(f"{contract.name}.{func.name}: {expr}")
                if len(found) >= 40:
                    return found
    return found


def _math_formulas(combined: str, types: Sequence[str]) -> List[str]:
    hits: List[str] = []
    for model in load_math_models():
        if model.get("protocol_types") and not (set(model["protocol_types"]) & set(types)):
            pass
        signals = model.get("signals") or []
        if any(signal.lower() in combined.lower() for signal in signals):
            hits.append(f"{model['id']}: {model['name']}")
    return hits


def _external_deps(ingestion: ProjectIngestion, combined: str) -> List[str]:
    deps: Set[str] = set()
    for match in re.finditer(r'import\s+(?:\{[^}]+}\s+from\s+)?["\']([^"\']+)["\']', combined):
        deps.add(match.group(1))
    for match in re.finditer(r'from\s+(\S+)\s+import', combined):
        deps.add(match.group(1))
    for manifest in ingestion.manifests:
        if manifest.kind in {"npm", "cargo", "python", "foundry", "move", "anchor"}:
            for match in re.finditer(
                r'"(@?[A-Za-z0-9_./-]+)"\s*:\s*"([^"]+)"',
                manifest.content,
            ):
                key = match.group(1)
                if key in {"version", "name", "license", "description", "main"}:
                    continue
                deps.add(f"{key}@{match.group(2)}")
    return sorted(deps)[:40]


def _architecture_notes(
    ctx: ProtocolContext,
    contracts: Sequence[ExtractedContract],
    types: Sequence[str],
    facts: Dict[str, bool],
) -> List[str]:
    notes = [
        f"Documented type={ctx.protocol_type}; inferred types={','.join(types)}.",
        f"{len(contracts)} contract/program unit(s) parsed.",
    ]
    if ctx.uses_multisig:
        notes.append("Docs claim a multisig; treat as unverified until the owner address is inspected.")
    if ctx.uses_timelock:
        notes.append("Docs claim a timelock; confirm the delay applies to every privileged path.")
    if facts.get("is_upgradeable"):
        notes.append("Upgrade surface present; implementation initialization and storage layout are in scope.")
    if facts.get("is_share_vault"):
        notes.append("Share/asset conversion detected — first-depositor and donation inflation are in scope.")
    if facts.get("donation_skips_health"):
        notes.append("Donation/reserve path looks like Euler donateToReserves: balance mutation without a health check.")
    if facts.get("permissionless_market_register"):
        notes.append("Permissionless market/strategy registration — treat callees as attacker-controlled (Penpie class).")
    if facts.get("unauthenticated_callback"):
        notes.append("Flash-loan/hook callback without an obvious caller bind (Prisma zap class).")
    if facts.get("clamm_tick_equality_risk"):
        notes.append("Kyber-style sqrtP / tick-boundary math — exact-tick mint+cross is in scope.")
    elif facts.get("concentrated_liquidity"):
        notes.append("Concentrated-liquidity math present — review tick-boundary equality and spoof tokens.")
    if facts.get("reward_measured_as_balance_delta"):
        notes.append("Harvest appears to credit a raw balance delta — re-entrant deposits can inflate rewards.")
    roles = sorted({c.role_guess for c in contracts})
    notes.append("Role guesses: " + ", ".join(f"{r}" for r in roles) + ".")
    return notes


def _summary(
    ctx: ProtocolContext,
    types: Sequence[str],
    contracts: Sequence[ExtractedContract],
    facts: Dict[str, bool],
) -> str:
    active = [key for key, value in sorted(facts.items()) if value]
    desc = (ctx.description or "").strip().replace("\n", " ")
    if len(desc) > 240:
        desc = desc[:237] + "..."
    return (
        f"{ctx.protocol_name} looks like a {', '.join(types)} protocol with "
        f"{len(contracts)} unit(s). {desc} "
        f"Active risk facts: {', '.join(active[:12]) or 'none'}."
    ).strip()
