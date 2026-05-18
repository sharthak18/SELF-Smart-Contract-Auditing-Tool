"""
SELF — Protocol-Specific Pack: Cross-Chain Bridges
Detectors from real bridge exploits — the most devastating attacks in Web3 history.

Real incidents encoded:
- Ronin Bridge ($625M) — missing signature validation
- Nomad Bridge ($190M) — zero-value message acceptance
- Wormhole ($320M) — missing signer verification
- Poly Network ($611M) — cross-chain auth bypass
- Multichain ($130M) — admin key compromise / approval exploit
- Hop Protocol — bonder manipulation
- Orbit Bridge ($82M) — multisig bypass

Sources: Immunefi bridge bounties, Rekt.news bridge analysis,
         Spearbit bridge audits, Trail of Bits cross-chain security,
         Code4rena bridge contests
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    content = file_ctx.content
    is_bridge = bool(re.search(
        r'(bridge|Bridge|crossChain|cross_chain|LayerZero|Wormhole|Axelar'
        r'|messageHash|rootHash|merkleRoot|chainId.*destination|destinationChain'
        r'|relayer|Relayer|guardian|validator.*set)',
        content, re.IGNORECASE
    ))
    if not is_bridge:
        return []

    issues = []
    _message_replay(file_ctx, content, issues)
    _signature_threshold(file_ctx, content, issues)
    _zero_value_message(file_ctx, content, issues)
    _merkle_root_validation(file_ctx, content, issues)
    _unbounded_token_mint(file_ctx, content, issues)
    _relayer_centralization(file_ctx, content, issues)
    _infinite_approval_bridge(file_ctx, content, issues)
    return issues


def _message_replay(file_ctx, content, issues):
    """
    BRIDGE-CRIT-001: Bridge messages can be replayed — no message hash tracking.
    Nomad pattern: same message processed multiple times.
    """
    has_process = bool(re.search(r'(function\s+process|executeMessage|handleMessage|receiveMessage)', content))
    if not has_process:
        return
    has_replay_guard = bool(re.search(
        r'(processedMessages|usedNonces|executedMessages|messageProcessed'
        r'|_isMessageProcessed|require.*processed)',
        content
    ))
    if not has_replay_guard:
        m = re.search(r'(function\s+process|executeMessage|handleMessage|receiveMessage)', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="BRIDGE-CRIT-001",
            title="Bridge: Message Replay — No Processed Message Tracking",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=5),
            description=(
                "The bridge message processing function does not track which messages "
                "have already been processed. An attacker can replay the same valid "
                "message multiple times, minting tokens or releasing funds repeatedly.\n\n"
                "**Real incident: Nomad Bridge ($190M, 2022)** — a single valid message "
                "was replayed hundreds of times by anyone watching the chain."
            ),
            exploit_scenario=(
                "1. Attacker observes a valid bridge message that releases tokens.\n"
                "2. Calls process() with the same message repeatedly.\n"
                "3. Each call releases tokens — bridge drained in minutes.\n"
                "4. The Nomad hack was copycat — anyone could replay it."
            ),
            remediation=(
                "```solidity\n"
                "mapping(bytes32 => bool) public processedMessages;\n\n"
                "function process(bytes calldata message) external {\n"
                "    bytes32 msgHash = keccak256(message);\n"
                "    require(!processedMessages[msgHash], 'Already processed');\n"
                "    processedMessages[msgHash] = true;\n"
                "    // ... execute message\n"
                "}\n"
                "```"
            ),
            references=["https://rekt.news/nomad-rekt/", "Immunefi: bridge-replay", "Spearbit: message-replay"],
            language="solidity",
        ))


def _signature_threshold(file_ctx, content, issues):
    """
    BRIDGE-CRIT-002: Insufficient validator/guardian threshold — < 2/3 majority.
    Ronin used 5/9 threshold — attacker compromised 5 keys.
    """
    has_multisig = bool(re.search(r'(threshold|required.*signature|minimumSignatures|quorum)', content))
    if not has_multisig:
        return
    # Look for low threshold values
    threshold_m = re.search(r'(threshold|required)\s*[=:]\s*(\d+)', content, re.IGNORECASE)
    total_m = re.search(r'(validatorCount|guardianCount|totalValidators)\s*[=:]\s*(\d+)', content, re.IGNORECASE)
    if threshold_m and total_m:
        try:
            threshold = int(threshold_m.group(2))
            total = int(total_m.group(2))
            if threshold < (total * 2 // 3):
                line = content[:threshold_m.start()].count('\n') + 1
                issues.append(Issue(
                    id="BRIDGE-CRIT-002",
                    title=f"Bridge: Low Validator Threshold {threshold}/{total} — Below 2/3 Majority",
                    severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    file=file_ctx.relative_path, line=line,
                    snippet=file_ctx.get_snippet(line, context=3),
                    description=(
                        f"The bridge requires {threshold}/{total} validator signatures "
                        f"({threshold/total*100:.0f}%), below the 2/3 supermajority standard. "
                        f"An attacker only needs to compromise {threshold} validators.\n\n"
                        f"**Real incident: Ronin Bridge ($625M)** used 5/9 threshold — "
                        f"attacker compromised 5 Ronin + 1 Axie DAO validator key."
                    ),
                    exploit_scenario=f"Attacker compromises {threshold} of {total} validator private keys (phishing, infra breach). Signs malicious withdrawal. Bridge drained.",
                    remediation=f"Increase threshold to at least ⌈{total} * 2/3⌉ = {(total*2)//3 + 1}/{total}. Use hardware security modules (HSM) for validator keys. Implement time delays for large withdrawals.",
                    references=["https://rekt.news/ronin-rekt/", "https://rekt.news/wormhole-rekt/"],
                    language="solidity",
                ))
        except (ValueError, ZeroDivisionError):
            pass


def _zero_value_message(file_ctx, content, issues):
    """
    BRIDGE-CRIT-003: Bridge accepts messages with zero/unset root (Nomad pattern).
    bytes32(0) treated as valid root.
    """
    zero_root = re.search(
        r'(acceptableRoot\s*\[\s*bytes32\s*\(\s*0\s*\)\s*\]'
        r'|roots\s*\[\s*0x0+\s*\]\s*=\s*true'
        r'|confirm.*0.*root|zero.*root.*valid)',
        content, re.IGNORECASE
    )
    # Also: if root is never validated against zero
    has_root_check = bool(re.search(r'root\s*!=\s*(bytes32\s*\(\s*0\s*\)|0x0)', content))
    has_root_use = bool(re.search(r'(merkleRoot|committedRoot|acceptedRoot)', content))

    if has_root_use and not has_root_check:
        m = re.search(r'(merkleRoot|committedRoot|acceptedRoot)', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="BRIDGE-CRIT-003",
            title="Bridge: Merkle Root Not Validated Against Zero — Nomad Attack Pattern",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "The bridge does not explicitly reject `bytes32(0)` as a valid Merkle root. "
                "The Nomad hack occurred because `bytes32(0)` was inadvertently set as an "
                "acceptable root during an upgrade, making any message with proof = 0x0 valid.\n\n"
                "**$190M was stolen in 2 hours by copy-pasting a single transaction.**"
            ),
            exploit_scenario="If bytes32(0) is a valid root, any attacker can craft a message with all-zero proof fields and it passes merkle verification.",
            remediation=(
                "```solidity\n"
                "require(root != bytes32(0), 'Zero root not acceptable');\n"
                "require(acceptableRoots[root], 'Root not confirmed');\n"
                "```"
            ),
            references=["https://rekt.news/nomad-rekt/", "Nomad post-mortem", "Immunefi: nomad-analysis"],
            language="solidity",
        ))


def _merkle_root_validation(file_ctx, content, issues):
    """
    BRIDGE-HIGH-001: Merkle proof verification without domain separation.
    Proof valid on one chain can be submitted on another.
    """
    has_merkle = bool(re.search(r'(merkle|MerkleProof|_verify|verifyProof)', content))
    if not has_merkle:
        return
    has_domain_sep = bool(re.search(
        r'(domainHash|DOMAIN_SEPARATOR|chainId.*leaf|leafHash.*chainId'
        r'|localDomain|remoteDomain)',
        content
    ))
    if not has_domain_sep:
        m = re.search(r'(MerkleProof|_verify|verifyProof)', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="BRIDGE-HIGH-001",
            title="Bridge: Merkle Proof Lacks Domain Separation — Cross-Chain Replay",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "Merkle proof leaves don't include the destination chain ID or domain hash. "
                "A proof valid on chain A can be submitted on chain B if the bridge is deployed "
                "at the same address — cross-chain replay attack."
            ),
            exploit_scenario="Bridge deployed on mainnet and Polygon. Attacker takes valid mainnet withdrawal proof and submits it on Polygon — double withdrawal.",
            remediation=(
                "Include chain ID in leaf hashing:\n"
                "```solidity\n"
                "bytes32 leaf = keccak256(abi.encodePacked(\n"
                "    block.chainid,  // Domain separation\n"
                "    recipient, amount, nonce\n"
                "));\n"
                "```"
            ),
            references=["Immunefi: cross-chain-replay", "Spearbit: bridge-domain"],
            language="solidity",
        ))


def _unbounded_token_mint(file_ctx, content, issues):
    """
    BRIDGE-CRIT-004: Wrapped token minting on destination chain without supply cap.
    Wormhole: $320M minted out of thin air due to missing signature verification.
    """
    has_mint = bool(re.search(r'(_mint|mint\s*\()', content))
    has_bridge_context = bool(re.search(r'(bridge|wrap|receiveMessage|executeMessage)', content))
    if not (has_mint and has_bridge_context):
        return
    has_supply_cap = bool(re.search(r'(maxSupply|totalSupply.*<=|cap\b|MAX_SUPPLY)', content))
    has_auth = bool(re.search(r'(onlyBridge|onlyRelayer|require.*msg\.sender.*bridge)', content))

    if not has_auth:
        m = re.search(r'_mint\s*\(|mint\s*\(', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="BRIDGE-CRIT-004",
            title="Bridge: Token Mint Without Authorization — Infinite Mint Risk",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "Wrapped token minting is called in a bridge context without verifying "
                "the caller is the authorized bridge contract. An attacker can directly "
                "call `mint()` to create unlimited tokens.\n\n"
                "**Real incident: Wormhole ($320M, 2022)** — signature verification "
                "was bypassable, allowing minting of 120,000 wETH out of thin air."
            ),
            exploit_scenario="Attacker calls mint() directly (or via bridge with forged proof) — mints unlimited wrapped tokens, drains the collateral backing pool.",
            remediation=(
                "```solidity\n"
                "address public immutable BRIDGE;\n"
                "function mint(address to, uint256 amount) external {\n"
                "    require(msg.sender == BRIDGE, 'Only bridge');\n"
                "    _mint(to, amount);\n"
                "}\n"
                "```"
            ),
            references=["https://rekt.news/wormhole-rekt/", "Immunefi: wormhole-analysis"],
            language="solidity",
        ))


def _relayer_centralization(file_ctx, content, issues):
    """
    BRIDGE-HIGH-002: Single relayer/operator without fallback — centralization + DoS.
    """
    has_relayer = bool(re.search(r'(relayer|Relayer|operator|sequencer)', content, re.IGNORECASE))
    if not has_relayer:
        return
    has_single_relayer = bool(re.search(r'(address\s+public\s+(relayer|operator)|onlyRelayer|onlyOperator)', content))
    has_fallback_relayer = bool(re.search(r'(fallbackRelayer|alternateRelayer|relayerSet|relayers\[)', content))

    if has_single_relayer and not has_fallback_relayer:
        m = re.search(r'(address\s+public\s+(relayer|operator))', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="BRIDGE-HIGH-002",
            title="Bridge: Single Relayer/Operator — Centralization + DoS Risk",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "The bridge relies on a single relayer/operator address with no fallback. "
                "If the relayer is compromised, goes offline, or is malicious, "
                "all cross-chain message delivery stops — bridge permanently DoS'd. "
                "Relayer can also censor or front-run messages."
            ),
            exploit_scenario="Relayer operator's server goes down. All pending bridge transactions are stuck indefinitely. Users cannot recover funds.",
            remediation="Use a decentralized relayer set or allow anyone to relay messages (with proper validation). Add a permissionless fallback relay path.",
            references=["Multichain security incident 2023", "Hop Protocol relayer design"],
            language="solidity",
        ))


def _infinite_approval_bridge(file_ctx, content, issues):
    """
    BRIDGE-HIGH-003: Bridge router uses infinite approve — Multichain pattern.
    If bridge is compromised, all user tokens with infinite approval are at risk.
    """
    has_max_approve = bool(re.search(r'(type\s*\(\s*uint256\s*\)\s*\.max|UINT_MAX|2\*\*256\s*-\s*1)', content))
    has_approve_call = bool(re.search(r'\.approve\s*\(\s*\w+\s*,\s*(type|UINT|2\*\*)', content))
    if has_max_approve and has_approve_call:
        m = re.search(r'\.approve\s*\(\s*\w+\s*,\s*(type|UINT|2\*\*)', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="BRIDGE-HIGH-003",
            title="Bridge: Infinite Token Approval — All User Funds at Risk if Bridge Compromised",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "The bridge uses `approve(spender, type(uint256).max)` — infinite approval. "
                "If the bridge contract or its admin is ever compromised, "
                "every user who approved this bridge loses ALL their tokens.\n\n"
                "**Real incident: Multichain ($130M, 2023)** — admin key compromise "
                "allowed draining of all wallets that had infinite approvals."
            ),
            exploit_scenario="Bridge admin key compromised. Attacker calls transferFrom() for every address that gave infinite approval — drains all token balances.",
            remediation="Use exact-amount approvals per transaction, or implement permit-based approvals (EIP-2612) that expire.",
            references=["https://rekt.news/multichain-rekt2/", "EIP-2612: permit"],
            language="solidity",
        ))
