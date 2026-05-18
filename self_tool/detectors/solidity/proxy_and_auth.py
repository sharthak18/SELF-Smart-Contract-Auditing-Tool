"""
SELF — SOL-CRIT-007/008/009/010
Proxy: Uninitialized + Storage Collision | tx.origin auth | Signature Replay

Low-FP strategy:
- Proxy issues: require BOTH proxy pattern indicators AND missing guard
- tx.origin: only flag when used in require/if for auth, not just referenced
- Sig replay: require BOTH signature verification AND missing nonce/chainId

Sources: OpenZeppelin, Trail of Bits, SWC-115/122, Immunefi, Spearbit, Sherlock findings
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content

    _check_uninitialized_proxy(file_ctx, content, issues)
    _check_storage_collision(file_ctx, content, issues)
    _check_tx_origin(file_ctx, content, issues)
    _check_signature_replay(file_ctx, content, issues)
    return issues


def _check_uninitialized_proxy(file_ctx, content, issues):
    """
    SOL-CRIT-007: Uninitialized proxy implementation.
    Requires: upgradeable pattern detected + initialize() not protected by initializer modifier
    """
    is_upgradeable = bool(re.search(
        r'(Initializable|UUPSUpgradeable|TransparentUpgradeableProxy'
        r'|_disableInitializers|__gap\s*\[)', content
    ))
    if not is_upgradeable:
        return

    # Look for initialize() without initializer/onlyInitializing modifier
    init_fn = re.compile(
        r'function\s+(initialize|init)\s*\([^)]*\)\s*([^{]*)\{',
        re.MULTILINE
    )
    for m in init_fn.finditer(content):
        attrs = m.group(2)
        # If protected, skip
        if re.search(r'\b(initializer|onlyInitializing|reinitializer)\b', attrs):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-CRIT-007",
            title="Upgradeable Proxy: `initialize()` Missing `initializer` Modifier",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file=file_ctx.relative_path,
            line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "This upgradeable contract has an `initialize()` function that lacks the "
                "`initializer` modifier from OpenZeppelin's `Initializable`. Without this guard, "
                "`initialize()` can be called multiple times — or by anyone on the "
                "implementation contract directly — allowing an attacker to take ownership "
                "and drain the protocol.\n\n"
                "**Real incidents:**\n"
                "- Wormhole (2022) — $320M at risk from uninitialized proxy\n"
                "- Popsicle Finance (2021) — $20M via re-initialization"
            ),
            exploit_scenario=(
                "1. Implementation contract is deployed but `initialize()` is not called immediately.\n"
                "2. Attacker calls `initialize(attackerAddress)` on the implementation directly.\n"
                "3. Attacker is now `owner` of the implementation — can call `upgradeTo(malicious)`.\n"
                "4. Protocol storage is wiped and funds drained."
            ),
            remediation=(
                "```solidity\n"
                "import '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';\n\n"
                "contract MyContract is Initializable {\n"
                "    function initialize(address owner) external initializer {\n"
                "        __Ownable_init(owner);\n"
                "    }\n"
                "}\n"
                "```\n"
                "Also call `_disableInitializers()` in the implementation constructor to lock it permanently."
            ),
            references=[
                "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
                "SWC-118",
                "https://rekt.news/popsicle-rekt/",
                "https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a",
            ],
            language="solidity",
        ))


def _check_storage_collision(file_ctx, content, issues):
    """
    SOL-CRIT-008: Proxy storage collision.
    Requires: proxy pattern AND non-EIP-1967 slot usage detected
    Only flag when both proxy inheritance AND state vars in same contract are present.
    """
    is_proxy = bool(re.search(
        r'(delegatecall|_implementation\s*\(\)|ERC1967|_IMPLEMENTATION_SLOT'
        r'|Proxy|fallback\s*\(\)\s*external)', content
    ))
    if not is_proxy:
        return

    # Check if state variables are declared at top-level (collision risk)
    # alongside a proxy/delegatecall usage
    has_state_vars = bool(re.search(
        r'^\s{0,4}(address|uint256|bool|mapping|bytes32)\s+(public|private|internal)?\s*\w+\s*;',
        content, re.MULTILINE
    ))
    uses_eip1967 = bool(re.search(r'(ERC1967|_IMPLEMENTATION_SLOT|keccak256.*eip1967)', content))

    if has_state_vars and not uses_eip1967:
        line = 1
        m = re.search(r'(delegatecall|_implementation)', content)
        if m:
            line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-CRIT-008",
            title="Proxy Storage Collision: State Variables May Overlap Implementation Slots",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path,
            line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "This proxy contract declares state variables without using EIP-1967 "
                "standardized storage slots. In a proxy pattern, both the proxy and "
                "implementation share the same storage layout. If a state variable in "
                "the proxy occupies the same slot as one in the implementation, writes "
                "from the implementation will corrupt the proxy's admin/ownership data.\n\n"
                "**Real incidents:**\n"
                "- Audius (2022) — $6M stolen via storage collision on governance proxy"
            ),
            exploit_scenario=(
                "1. Proxy stores `address public implementation` at slot 0.\n"
                "2. Implementation also stores `address public owner` at slot 0.\n"
                "3. When implementation sets `owner`, it overwrites `implementation` address.\n"
                "4. All subsequent calls delegatecall to attacker-controlled address."
            ),
            remediation=(
                "Use **EIP-1967 unstructured storage** for all proxy admin variables:\n"
                "```solidity\n"
                "bytes32 private constant _IMPL_SLOT =\n"
                "    bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1);\n"
                "```\n"
                "Or use OpenZeppelin's `ERC1967Proxy` / `TransparentUpgradeableProxy` "
                "which handle this correctly."
            ),
            references=[
                "EIP-1967",
                "https://rekt.news/audius-rekt/",
                "https://docs.openzeppelin.com/contracts/4.x/api/proxy#ERC1967Upgrade",
            ],
            language="solidity",
        ))


def _check_tx_origin(file_ctx, content, issues):
    """
    SOL-CRIT-009: tx.origin used for authentication.
    Low-FP: only flag when tx.origin is inside require() or if() for auth,
    NOT when used for informational purposes (e.g. event logging).
    """
    # Specifically: require(tx.origin == ...) or if(tx.origin == ...) for gating
    auth_pattern = re.compile(
        r'(require\s*\(\s*tx\.origin|if\s*\(\s*tx\.origin\s*==|tx\.origin\s*==\s*\w+\s*[,)])',
        re.MULTILINE
    )
    for m in auth_pattern.finditer(content):
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-CRIT-009",
            title="Authentication via `tx.origin` — Phishing Attack Vector",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file=file_ctx.relative_path,
            line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "`tx.origin` is the **original EOA** that initiated the transaction chain. "
                "Using it for authorization allows phishing attacks: if a legitimate user is "
                "tricked into calling a malicious contract, that contract can relay calls "
                "to the victim contract — `tx.origin` is still the victim's address, "
                "bypassing the auth check.\n\n"
                "**Always use `msg.sender` for authorization.**"
            ),
            exploit_scenario=(
                "1. Victim owns a contract that uses `require(tx.origin == owner)`.\n"
                "2. Attacker tricks victim into calling `MaliciousContract.attack()`.\n"
                "3. `MaliciousContract` calls `VictimContract.withdraw(attackerAddr)`.\n"
                "4. `tx.origin == victim (owner)` passes — funds sent to attacker."
            ),
            remediation=(
                "Replace `tx.origin` with `msg.sender` for all authorization:\n"
                "```solidity\n"
                "// ❌ Vulnerable\n"
                "require(tx.origin == owner);\n\n"
                "// ✅ Safe\n"
                "require(msg.sender == owner, 'Not owner');\n"
                "```\n"
                "`tx.origin` is only acceptable for **anti-bot checks** (EOA-only calls), "
                "but even then `msg.sender == tx.origin` is preferred."
            ),
            references=["SWC-115", "https://swcregistry.io/docs/SWC-115", "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/"],
            language="solidity",
        ))


def _check_signature_replay(file_ctx, content, issues):
    """
    SOL-CRIT-010: Signature replay — missing nonce or chainId.
    Low-FP: only flag when ecrecover/ECDSA is used AND nonce/chainId both absent.
    """
    uses_sig = bool(re.search(r'(ecrecover\s*\(|ECDSA\.recover|SignatureChecker)', content))
    if not uses_sig:
        return

    has_nonce = bool(re.search(r'\b(nonce|nonces|_nonce|userNonce)\b', content, re.IGNORECASE))
    has_chainid = bool(re.search(r'\b(chainId|block\.chainid|CHAIN_ID|_chainId)\b', content, re.IGNORECASE))
    has_eip712 = bool(re.search(r'(EIP712|_domainSeparatorV4|DOMAIN_SEPARATOR)', content))

    # Only flag if BOTH nonce AND chainId protections are missing, and no EIP-712
    if has_nonce or has_chainid or has_eip712:
        return

    m = re.search(r'(ecrecover\s*\(|ECDSA\.recover)', content)
    if not m:
        return
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-CRIT-010",
        title="Signature Replay Attack: Missing Nonce and ChainId in Signature Verification",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file=file_ctx.relative_path,
        line=line,
        snippet=file_ctx.get_snippet(line, context=4),
        description=(
            "The contract verifies ECDSA signatures without including a **nonce** or "
            "**chainId** in the signed message. This allows:\n"
            "1. **Replay attacks** — a signature used once can be replayed repeatedly.\n"
            "2. **Cross-chain replay** — signatures valid on mainnet reused on a fork/L2.\n\n"
            "**Real incidents:** Many bridge and meta-transaction hacks exploited missing nonces."
        ),
        exploit_scenario=(
            "1. User signs a message authorizing `withdraw(1000 USDC)`.\n"
            "2. Attacker captures the signature from the mempool or a past transaction.\n"
            "3. Attacker replays the same signature to call `withdraw()` again.\n"
            "4. Without a nonce, the signature is still valid — funds drained repeatedly."
        ),
        remediation=(
            "Use **EIP-712** structured signing with nonce and chainId:\n"
            "```solidity\n"
            "import '@openzeppelin/contracts/utils/cryptography/EIP712.sol';\n\n"
            "bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(\n"
            "    keccak256('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)'),\n"
            "    owner, spender, value, nonces[owner]++, deadline\n"
            ")));\n"
            "address signer = ECDSA.recover(digest, v, r, s);\n"
            "```"
        ),
        references=[
            "SWC-121",
            "EIP-712",
            "https://swcregistry.io/docs/SWC-121",
            "https://eips.ethereum.org/EIPS/eip-712",
        ],
        language="solidity",
    ))
