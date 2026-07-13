"""Deterministic, fully local review guidance for every shipped detector."""

from dataclasses import dataclass
from typing import Dict, Iterable, List

from self_tool.core.issue import Confidence, Issue, Severity


STATUS_STATIC_MATCH = "STATIC_MATCH"
STATUS_CONTEXT_REQUIRED = "CONTEXT_REQUIRED"
STATUS_MANUAL_PROOF = "MANUAL_PROOF"
STATUS_INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class ReviewProfile:
    lens: str
    proof: str
    test: str


def _profile(lens: str, proof: str, test: str) -> ReviewProfile:
    return ReviewProfile(lens=lens, proof=proof, test=test)


REVIEW_PROFILES: Dict[str, ReviewProfile] = {
    "HUFF-CRIT-001": _profile("EVM stack safety", "Trace stack height through every macro branch and prove each opcode has enough operands.", "Execute boundary calldata through every macro branch and assert no stack underflow."),
    "MOV-CRIT-001": _profile("Move authorization", "Prove every state-changing entry function receives and validates the intended signer.", "Call the entry function from an unauthorized signer and require an abort."),
    "MOV-CRIT-002": _profile("Move global storage", "Match each global resource borrow to an explicit acquires declaration and authorized resource address.", "Exercise the resource path against absent, wrong-address, and valid resources."),
    "SOL-RUST-001": _profile("Solana signer authorization", "Trace the account constraint and prove the privileged account is required to be a signer.", "Submit the instruction with the signer bit removed and require failure."),
    "SOL-RUST-003": _profile("Solana CPI trust", "Prove the invoked program ID is constrained to the expected executable program.", "Substitute an attacker-controlled program account and require rejection."),
    "AMM-CRIT-001": _profile("AMM invariant", "Compute reserves before and after the swap, including fees, and prove the configured invariant cannot decrease.", "Fuzz both swap directions and assert the post-swap invariant and reserve accounting."),
    "AMM-CRIT-002": _profile("AMM reserve accounting", "Separate unsolicited token donations from accounted deposits and show donations cannot alter pricing or shares.", "Donate tokens directly before swap and liquidity operations and assert no value extraction."),
    "BRIDGE-CRIT-001": _profile("Bridge replay protection", "Identify the canonical message ID and prove it is consumed exactly once across all execution paths.", "Relay the same valid message twice and require the second execution to fail."),
    "BRIDGE-CRIT-002": _profile("Bridge validator quorum", "Derive the effective signer threshold and prove it meets the protocol's Byzantine-fault assumption.", "Test duplicate, malformed, below-threshold, and threshold signatures."),
    "BRIDGE-CRIT-003": _profile("Bridge root validation", "Prove zero, unset, expired, and replaced roots cannot authorize messages.", "Submit a proof against zero and uninitialized roots and require rejection."),
    "BRIDGE-CRIT-004": _profile("Bridge mint authorization", "Trace every destination mint to authenticated source-chain burn or lock evidence and a supply bound.", "Attempt direct, replayed, and over-cap mint messages."),
    "LEND-CRIT-001": _profile("Lending solvency", "Prove liquidation thresholds retain a safety buffer under fees, oracle delay, and price movement.", "Fuzz collateral factors around the liquidation threshold and assert bad debt cannot appear instantly."),
    "LEND-CRIT-002": _profile("Share inflation", "Model first-deposit, donation, rounding, and empty-market states and prove shares cannot be cheaply inflated.", "Run first-depositor donation attacks across minimum deposit values."),
    "SOL-CRIT-001": _profile("Reentrancy ordering", "Trace the external call and every affected storage write, proving state is settled before callback control.", "Use a callback contract to re-enter the same function before the first invocation completes."),
    "SOL-CRIT-002": _profile("Cross-function reentrancy", "Build the shared-state call graph and prove no callback can enter another function while invariants are transient.", "Re-enter each sibling public function from every external call site."),
    "SOL-CRIT-003": _profile("Read-only reentrancy", "Identify view functions exposing transient state during an external callback and downstream consumers of that state.", "Read the affected view from a callback and use it in a dependent protocol action."),
    "SOL-CRIT-004": _profile("External call result handling", "Prove success and return data are validated before state records the operation as complete.", "Force the callee to revert or return false and assert caller state is unchanged."),
    "SOL-CRIT-005": _profile("Delegatecall target control", "Trace the delegatecall target to an immutable or strongly authorized allowlist and validate code identity.", "Supply an attacker implementation and require rejection before delegatecall."),
    "SOL-CRIT-006": _profile("Destruction authorization", "Prove selfdestruct is unreachable by unauthorized callers and evaluate current-chain EIP-6780 semantics.", "Call the destruction path from arbitrary accounts and after initialization changes."),
    "SOL-CRIT-007": _profile("Proxy initialization", "Prove implementation and proxy initialization are one-time, ordered, and inaccessible to front-runners.", "Race initialization and attempt repeated initialization on proxy and implementation."),
    "SOL-CRIT-008": _profile("Proxy storage layout", "Compare implementation layouts across inheritance and upgrades, including reserved slots and gaps.", "Run storage-layout diff tests and verify state survives a representative upgrade."),
    "SOL-CRIT-009": _profile("Authentication origin", "Trace authorization to msg.sender or validated signatures and remove all tx.origin trust.", "Call through a phishing intermediary and prove privilege cannot be inherited."),
    "SOL-CRIT-010": _profile("Signature replay", "Prove signatures bind nonce, chain ID, contract, action, parameters, and expiration.", "Replay across nonce, chain, contract, parameter, and deadline boundaries."),
    "SOL-TAINT-001": _profile("Tainted destruction recipient", "Trace the selfdestruct recipient from user input and prove authorization or fixed destination.", "Pass attacker-controlled recipients through every assignment path."),
    "SOL-TAINT-002": _profile("Tainted delegatecall", "Trace user-controlled data to the delegatecall target and calldata without losing sanitization steps.", "Fuzz target and calldata with attacker contracts and require validation."),
    "STAKE-CRIT-001": _profile("Reward checkpoint ordering", "Prove global and user reward checkpoints update before every balance or total-supply mutation.", "Deposit, transfer, withdraw, and claim around reward updates and compare earned rewards."),
    "STAKE-CRIT-002": _profile("Reward claim reentrancy", "Prove claimable state is cleared before token or native-value transfer.", "Re-enter claim from the reward token hook or native receive function."),
    "VYP-CRIT-001": _profile("Vyper reentrancy locking", "Verify compiler version and lock coverage across every external state-changing path sharing state.", "Re-enter through raw_call and token hooks across sibling functions."),
    "VYP-CRIT-002": _profile("Vyper raw_call result", "Prove raw_call failure and returned data are checked before state changes.", "Use a reverting and false-returning target and assert atomic failure."),
    "HUFF-HIGH-001": _profile("Huff control flow", "Trace every MAIN dispatch branch to STOP, RETURN, REVERT, or SELFDESTRUCT.", "Fuzz selectors and calldata lengths and reject unintended fallthrough."),
    "HUFF-HIGH-002": _profile("Huff call value", "Prove nonpayable dispatch paths reject CALLVALUE before state changes.", "Send nonzero value to every selector and assert only intended payable paths accept it."),
    "MOV-HIGH-001": _profile("Move capability authorization", "Trace capability creation, storage, borrowing, and holder validation.", "Attempt capability use from copied, wrong-holder, and absent-resource contexts."),
    "MOV-HIGH-002": _profile("Move arithmetic bounds", "Derive numeric bounds for each arithmetic expression and prove abort behavior cannot lock funds.", "Fuzz zero, one, maximum, and near-overflow operands."),
    "MOV-HIGH-003": _profile("Move global-state authorization", "Prove each global write is gated by signer, capability, or resource ownership.", "Invoke each write from an unrelated signer and require abort."),
    "SOL-RUST-002": _profile("Solana account ownership", "Prove every deserialized mutable account is owned by the expected program.", "Substitute same-layout accounts owned by an attacker program."),
    "SOL-RUST-004": _profile("Solana PDA derivation", "Recompute the PDA with canonical bump and bind every seed to intended inputs.", "Try alternate bumps, reordered seeds, and attacker-chosen seed values."),
    "SOL-RUST-005": _profile("Rust arithmetic bounds", "Prove checked arithmetic or bounded inputs for all value-bearing calculations in release mode.", "Fuzz maximum integer values under release compilation."),
    "AMM-HIGH-001": _profile("AMM slippage", "Prove every value-changing AMM operation enforces user-defined minimum output or maximum input.", "Move price before execution and assert the transaction reverts outside tolerance."),
    "AMM-HIGH-002": _profile("AMM initial liquidity", "Prove initial shares cannot be inflated and a permanent minimum-liquidity floor exists where required.", "Fuzz first mint with donations and asymmetric token amounts."),
    "AMM-HIGH-003": _profile("Nonstandard token accounting", "Compare requested and actual token balance deltas for fee-on-transfer and rebasing behavior.", "Use fee-on-transfer and rebasing token fixtures for deposit, swap, and withdrawal."),
    "AMM-HIGH-004": _profile("Liquidity timing", "Prove same-transaction liquidity cannot capture fees, rewards, or manipulated accounting.", "Add and remove liquidity around swaps and reward distribution in one transaction."),
    "BRIDGE-HIGH-001": _profile("Bridge domain separation", "Prove signed or proven messages bind source chain, destination chain, lane, contract, and action.", "Replay a valid proof across chains, lanes, and destination contracts."),
    "BRIDGE-HIGH-002": _profile("Bridge liveness", "Identify relayer failure modes and prove users retain a permissionless or redundant completion path.", "Disable the primary relayer and exercise timeout, retry, and alternate relay paths."),
    "BRIDGE-HIGH-003": _profile("Bridge allowance exposure", "Bound token allowances and prove compromise of a router cannot drain unrelated balances.", "Replace or compromise the approved spender and measure maximum extractable value."),
    "LEND-HIGH-001": _profile("Interest accrual", "Prove every debt, collateral, liquidation, and exchange-rate action accrues all relevant markets first.", "Advance time between actions and compare against a continuously accrued reference model."),
    "LEND-HIGH-002": _profile("Bad debt handling", "Model insolvency creation, recognition, socialization, and recovery without blocking healthy users.", "Force an undercollateralized account and exercise liquidation and withdrawal paths."),
    "LEND-HIGH-003": _profile("Liquidation authorization", "Prove borrowers cannot capture their own liquidation incentive directly or through aliases.", "Liquidate self through direct, delegated, and proxy accounts."),
    "LEND-HIGH-004": _profile("Collateral oracle integrity", "Trace collateral pricing to manipulation-resistant data with freshness and decimal checks.", "Manipulate pool reserves in one transaction and assert borrowing power is unchanged."),
    "SOL-HIGH-001": _profile("Oracle manipulation", "Prove price inputs use sufficient liquidity, window, freshness, and independent validation.", "Move spot price with temporary liquidity and compare protocol valuation."),
    "SOL-HIGH-002": _profile("Legacy arithmetic", "Identify every unchecked pre-0.8 arithmetic path and prove bounds or SafeMath coverage.", "Fuzz maximum and minimum values on pre-0.8 compilation."),
    "SOL-HIGH-003": _profile("Unchecked arithmetic", "Prove every unchecked block has explicit mathematical bounds that dominate all inputs.", "Fuzz values immediately below, at, and above each proven bound."),
    "SOL-HIGH-004": _profile("Flash-loan callback authentication", "Bind callback caller, initiator, asset, amount, fee, and operation state.", "Call the callback directly and with mismatched loan parameters."),
    "SOL-HIGH-005": _profile("Critical access control", "Enumerate intended callers and prove modifiers or internal checks enforce that set.", "Invoke the function from arbitrary EOAs, contracts, and delegated callers."),
    "SOL-HIGH-006": _profile("Allowance race", "Prove allowance changes cannot spend both old and new values during transaction ordering.", "Front-run allowance replacement with spending of the existing allowance."),
    "SOL-HIGH-007": _profile("Gas-bounded iteration", "Derive the maximum iterable collection size and prove all callers can make progress.", "Grow the collection until near block gas limits and test pagination or pull paths."),
    "SOL-HIGH-008": _profile("Token transfer result", "Prove false returns, missing returns, and reverts are handled consistently.", "Use standard, false-returning, no-return, and reverting token fixtures."),
    "SOL-HIGH-009": _profile("MEV and slippage", "Prove user value bounds and deadlines survive adversarial transaction ordering.", "Simulate front-run and back-run price movement around the operation."),
    "SOL-HIGH-010": _profile("Randomness", "Prove outcomes cannot be predicted or biased by validators or transaction submitters.", "Search feasible timestamps and block inputs for outcome bias."),
    "SOL-HIGH-011": _profile("Precision ordering", "Quantify truncation from division-before-multiplication and identify who benefits.", "Differential-test against full-precision mulDiv over boundary values."),
    "SOL-HIGH-012": _profile("Governance flash loans", "Prove voting power uses historical checkpoints and execution has a review delay.", "Borrow voting tokens temporarily, propose, vote, and attempt same-window execution."),
    "SOL-HIGH-013": _profile("Initializer replay", "Prove initialization is one-time and ownership cannot be overwritten after deployment.", "Call initialize before, during, and after the expected deployment sequence."),
    "SOL-TAINT-003": _profile("Tainted value transfer", "Trace user-controlled amounts to value transfer and prove balance, cap, and authorization checks.", "Fuzz amount through aliases and arithmetic transformations."),
    "STAKE-HIGH-001": _profile("Reward accumulator bounds", "Derive accumulator growth bounds across maximum duration, rate, and precision scale.", "Advance maximum time and stake values near integer limits."),
    "STAKE-HIGH-002": _profile("Reward timing", "Prove short-lived stake cannot capture rewards earned before entry.", "Deposit immediately before distribution and withdraw immediately after."),
    "STAKE-HIGH-003": _profile("Shared staking/reward token", "Separate principal from rewards when both use the same token balance.", "Stake, fund rewards, claim, and withdraw in adversarial order."),
    "VYP-HIGH-001": _profile("Vyper slice bounds", "Prove offset and length remain within source data for every caller-controlled combination.", "Fuzz zero, exact-end, and out-of-range slice parameters."),
    "VYP-HIGH-002": _profile("Vyper exponentiation bounds", "Bound base and exponent and account for compiler-version behavior.", "Fuzz maximum base and exponent values around overflow thresholds."),
    "HUFF-MED-001": _profile("Huff calldata dispatch", "Prove calldata shorter than four bytes cannot select or fall through to privileged logic.", "Execute calldata lengths zero through four for every dispatcher branch."),
    "SOL-RUST-006": _profile("Solana account reload", "Prove account data read after CPI is reloaded before authorization or accounting use.", "Mutate the account in CPI and verify subsequent logic observes the new value."),
    "AMM-MED-001": _profile("AMM square-root precision", "Quantify sqrt rounding direction and prove it cannot overmint shares or undercharge users.", "Differential-test perfect squares and adjacent values."),
    "LEND-MED-001": _profile("Borrow concentration", "Derive per-asset and global exposure limits under oracle and liquidity stress.", "Borrow to configured limits across correlated accounts and assets."),
    "SOL-MED-001": _profile("Privileged control", "Enumerate owner powers, delays, multisig thresholds, and maximum immediate fund impact.", "Exercise each privileged action from compromised and transferred-role scenarios."),
    "SOL-MED-002": _profile("Address validation", "Prove zero and sentinel addresses cannot become critical recipients, owners, or dependencies.", "Pass zero address to every affected setter and constructor."),
    "SOL-MED-003": _profile("Transaction expiry", "Prove time-sensitive operations enforce a caller-controlled deadline.", "Delay signed or pending operations beyond the intended validity window."),
    "SOL-MED-004": _profile("Oracle freshness", "Validate round completion, positive answer, timestamps, heartbeat, and sequencer state where applicable.", "Return stale, incomplete, zero, negative, and future-dated oracle rounds."),
    "SOL-MED-005": _profile("Token-hook reentrancy", "Trace ERC777 or callback hooks through all transient accounting states.", "Use a hook-enabled token to re-enter deposit, withdraw, and claim paths."),
    "SOL-MED-006": _profile("Event completeness", "Match critical state transitions to events carrying old/new values and affected actors.", "Execute each transition and assert the expected indexed event fields."),
    "SOL-MED-007": _profile("Integer narrowing", "Prove the source value fits the destination type before every downcast.", "Fuzz at destination maximum and one unit above."),
    "SOL-MED-008": _profile("Percentage precision", "Quantify rounding loss and prove direction is intentional and bounded.", "Compare reordered and full-precision calculations across small values."),
    "SOL-MED-009": _profile("Gas forwarding", "Prove hardcoded gas remains sufficient across opcode repricing and cannot grief state progress.", "Vary callee gas consumption around the fixed stipend."),
    "SOL-MED-010": _profile("ERC-4626 inflation", "Model empty vault, donations, virtual shares/assets, decimals, and rounding direction.", "Run first-deposit donation attacks across asset decimals."),
    "SOL-MED-011": _profile("Push-payment liveness", "Prove one recipient cannot block progress for all recipients.", "Include reverting and gas-consuming recipients in the batch."),
    "SOL-MED-012": _profile("Looped msg.value accounting", "Prove aggregate credited value never exceeds msg.value across loop iterations.", "Fuzz recipient count and per-iteration amount against total ETH supplied."),
    "STAKE-MED-001": _profile("Emergency reward accounting", "Prove emergency exit preserves or intentionally forfeits accrued rewards without trapping funds.", "Accrue rewards, trigger emergency exit, and reconcile principal and rewards."),
    "SOL-LOW-001": _profile("Compiler reproducibility", "Pin a compiler version and prove deployed bytecode matches the reviewed build.", "Build with every version accepted by the pragma and compare behavior."),
    "SOL-LOW-002": _profile("Compiler security", "Map the compiler version to known bugs and verify affected features are absent.", "Recompile with a maintained version and compare tests and bytecode assumptions."),
    "SOL-LOW-003": _profile("Variable shadowing", "Resolve every identifier to its declaration and prove shadowing cannot hide intended state writes.", "Exercise the function and assert the expected storage variable changes."),
    "SOL-LOW-004": _profile("Network-specific address", "Prove each hardcoded address is correct for every supported chain and immutable by design.", "Run deployment checks against wrong-chain and no-code addresses."),
    "SOL-LOW-005": _profile("Unlabeled constants", "Identify the unit, bound, and governance intent of each security-sensitive literal.", "Test values around each literal boundary."),
    "SOL-LOW-006": _profile("Security documentation", "Document caller trust, value movement, side effects, invariants, and failure modes.", "Review NatSpec against implementation and generated interfaces."),
    "SOL-LOW-007": _profile("Deprecated semantics", "Confirm deprecated language features cannot alter control flow or hashing semantics.", "Compile with the pinned compiler and migrate to supported equivalents."),
    "SOL-INFO-001": _profile("Assembly review", "Manually prove memory safety, storage slots, returndata bounds, and control flow in each assembly block.", "Fuzz calldata, returndata, and memory boundaries around the assembly."),
    "SOL-INFO-002": _profile("Upgrade discipline", "Document proxy type, admin model, initializer sequence, storage layout, and upgrade authorization.", "Upgrade through the production path and assert state and authorization invariants."),
    "SOL-INFO-003": _profile("External dependency trust", "Enumerate dependency addresses, upgradeability, failure modes, and emergency behavior.", "Simulate dependency revert, pause, malicious return data, and address change."),
    "VYP-INFO-001": _profile("Vyper compiler security", "Map the pinned Vyper version to advisories and verify affected constructs.", "Recompile with a maintained Vyper release and rerun security regression tests."),
    "SOL-CRIT-011": _profile("Transient storage", "Prove tstore is cleared before exiting the transaction.", "Use leftover transient data in a subsequent cross-contract call within the same tx."),
    "SOL-CRIT-012": _profile("CREATE2 reentrancy", "Verify the metamorphic contract hash before callback interaction.", "Deploy, destruct, and redeploy malicious bytecode at the same CREATE2 address."),
    "SOL-CRIT-014": _profile("Signature malleability", "Prove the 's' value of ECDSA signature is validated against the upper bound.", "Submit a morphed signature `(v', r, -s mod n)` to replay a transaction."),
    "SOL-HIGH-014": _profile("ERC20 approve race", "Ensure zero allowance state transition or use increase/decrease allowance.", "Front-run an approve transaction to spend both old and new allowances."),
    "SOL-HIGH-016": _profile("NFT safeTransferFrom", "Prove the receiver is checked for ERC721 receiver support.", "Send the NFT to an unsupported contract, locking it permanently."),
    "SOL-HIGH-018": _profile("Predictable commit hash", "Ensure msg.sender is bound into the commit keccak hash.", "Front-run the reveal transaction and duplicate the plaintext commit."),
    "SOL-HIGH-019": _profile("Slippage protection", "Enforce minAmountOut and strict deadline during swaps.", "Sandwich the transaction to extract maximum MEV value."),
    "SOL-HIGH-020": _profile("Upgradeable storage gap", "Provide a __gap variable for base upgradeable contracts.", "Upgrade the base contract and shift the layout of child contracts."),
    "SOL-HIGH-023": _profile("ecrecover zero", "Check if ecrecover returned address(0) to prevent unauthenticated actions.", "Submit an invalid signature to execute actions as address(0)."),
    "SOL-HIGH-024": _profile("Returndata bomb", "Limit returndatacopy or use assembly for calls without return values.", "Return a massive memory array to exhaust the caller's gas."),
    "SOL-LOW-008": _profile("Missing receive ETH", "Add receive() when handling WETH unwrapping.", "Unwrap WETH to native ETH and watch the fallback fail."),
    "SOL-LOW-009": _profile("Payable ignores value", "Ensure msg.value is processed or remove the payable modifier.", "Send ETH to the contract and observe it locked forever."),
    "SOL-MED-014": _profile("Permit deadline", "Validate block.timestamp against the permit deadline.", "Submit an old permit signature long after its intended expiration."),
}


def validate_review_profiles(detector_ids: Iterable[str]) -> None:
    expected = set(detector_ids)
    configured = set(REVIEW_PROFILES)
    missing = sorted(expected - configured)
    extra = sorted(configured - expected)
    if missing or extra:
        raise ValueError(
            "built-in review profile mismatch: "
            f"missing={missing or 'none'}, extra={extra or 'none'}"
        )


def review_issue(issue: Issue) -> Issue:
    profile = REVIEW_PROFILES.get(issue.id)
    if profile is None:
        raise ValueError(f"no built-in review profile for finding ID {issue.id}")
    if issue.severity == Severity.INFO:
        status = STATUS_INFORMATIONAL
    elif issue.context_note or issue.confidence == Confidence.LOW:
        status = STATUS_CONTEXT_REQUIRED
    elif issue.confidence == Confidence.HIGH and issue.snippet:
        status = STATUS_STATIC_MATCH
    else:
        status = STATUS_MANUAL_PROOF

    issue.review_status = status
    issue.review_reasoning = (
        f"Lens: {profile.lens}. Proof obligation: {profile.proof}"
    )
    issue.review_test = profile.test
    issue.review_engine = "SELF built-in deterministic reviewer"
    return issue


def review_issues(issues: List[Issue]) -> List[Issue]:
    for issue in issues:
        review_issue(issue)
    return issues
