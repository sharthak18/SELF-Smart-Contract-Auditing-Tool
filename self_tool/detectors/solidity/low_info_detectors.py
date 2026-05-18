"""
SELF — LOW and INFO severity detectors for Solidity
Sources: Slither, Aderyn, SWC Registry, Pashov methodology, OpenZeppelin best practices
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content
    _floating_pragma(file_ctx, content, issues)
    _outdated_compiler(file_ctx, content, issues)
    _shadowed_variable(file_ctx, content, issues)
    _hardcoded_address(file_ctx, content, issues)
    _magic_numbers(file_ctx, content, issues)
    _assembly_usage(file_ctx, content, issues)
    _upgradeable_detected(file_ctx, content, issues)
    _external_dependency(file_ctx, content, issues)
    _missing_natspec(file_ctx, content, issues)
    _deprecated_functions(file_ctx, content, issues)
    return issues


def _floating_pragma(file_ctx, content, issues):
    """SOL-LOW-001: Floating pragma (^) allows compilation with untested versions."""
    pattern = re.compile(r'pragma\s+solidity\s+(\^[0-9.]+)', re.MULTILINE)
    m = pattern.search(content)
    if m:
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-LOW-001",
            title=f"Floating Pragma: `{m.group(1)}` — Version Not Locked",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=1),
            description=(
                "A floating pragma (`^`) means the contract can be compiled with any "
                "compatible version. Newer compiler versions may have different behaviors "
                "or introduce bugs. Production contracts should lock to a specific version."
            ),
            exploit_scenario="Contract compiled with a newer buggy compiler version behaves differently than tested, causing unexpected vulnerabilities.",
            remediation=f"Lock the pragma: `pragma solidity {m.group(1).replace('^','')};`",
            references=["SWC-103", "Slither: solc-version"],
            language="solidity",
        ))


def _outdated_compiler(file_ctx, content, issues):
    """SOL-LOW-002: Compiler version older than 0.8.18 — known bugs."""
    m = re.search(r'pragma\s+solidity\s+\^?(\d+)\.(\d+)\.?(\d*)', content)
    if not m:
        return
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    if major == 0 and minor < 8:
        return  # Already caught by SOL-HIGH-002
    if major == 0 and minor == 8 and patch < 18:
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-LOW-002",
            title=f"Outdated Compiler Version: `{m.group(1)}.{m.group(2)}.{m.group(3)}`",
            severity=Severity.LOW, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=1),
            description=(
                f"Solidity {m.group(1)}.{m.group(2)}.{m.group(3)} has known bugs. "
                "Versions <0.8.18 have the `abi.encode` optimizer bug; <0.8.15 have "
                "data corruption bugs in certain inline assembly patterns."
            ),
            exploit_scenario="Known compiler bugs may cause incorrect code generation in specific patterns.",
            remediation="Upgrade to Solidity >=0.8.20 (latest stable).",
            references=["https://github.com/ethereum/solidity/releases", "Slither: solc-version"],
            language="solidity",
        ))


def _shadowed_variable(file_ctx, content, issues):
    """SOL-LOW-003: State variable shadowed by local variable in function."""
    # Find state variable names
    state_vars = re.findall(
        r'^\s{0,4}(?:address|uint\d*|int\d*|bool|bytes\d*|string|mapping)\s+'
        r'(?:public|private|internal)?\s*(?:immutable|constant)?\s*(\w+)\s*[=;]',
        content, re.MULTILINE
    )
    if not state_vars:
        return
    for var in set(state_vars):
        if len(var) < 3:
            continue
        # Find local declaration with same name inside function
        local_pattern = re.compile(
            rf'function\s+\w+[^{{]*\{{[^}}]*\b(?:uint\d*|address|bool|int\d*)\s+{re.escape(var)}\b',
            re.MULTILINE | re.DOTALL
        )
        m = local_pattern.search(content)
        if m:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-LOW-003",
                title=f"Shadowed State Variable: `{var}` Redeclared in Function",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=f"Local variable `{var}` shadows the state variable of the same name. This causes the function to operate on the local copy instead of storage, potentially missing important updates.",
                exploit_scenario=f"Function modifies local `{var}` thinking it's updating state. Storage remains unchanged — logic flaw.",
                remediation=f"Rename the local variable (e.g., `_{var}` or `local{var.capitalize()}`) to avoid confusion.",
                references=["SWC-119", "Slither: shadowing-local"],
                language="solidity",
            ))


def _hardcoded_address(file_ctx, content, issues):
    """SOL-LOW-004: Hardcoded Ethereum addresses in source code."""
    # Real addresses (40 hex chars) that aren't well-known constants
    pattern = re.compile(r'\b0x[0-9a-fA-F]{40}\b')
    known_zero = {'0x0000000000000000000000000000000000000000',
                  '0x000000000000000000000000000000000000dEaD'}
    found = set()
    for m in pattern.finditer(content):
        addr = m.group(0).lower()
        if addr in known_zero or addr in found:
            continue
        found.add(addr)
        # Only flag if not in a comment or test file
        if 'test' in file_ctx.relative_path.lower():
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-LOW-004",
            title=f"Hardcoded Address: `{m.group(0)}`",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=2),
            description="Hardcoded addresses make the contract non-portable across networks and require redeployment if addresses change (e.g., protocol upgrades).",
            exploit_scenario="Hardcoded address is outdated after a protocol migration — funds sent to deprecated contract.",
            remediation="Store addresses as immutable constructor parameters or configurable state variables.",
            references=["Solodit: hardcoded-address"],
            language="solidity",
        ))
        if len(found) >= 3:
            break  # Cap to avoid noise


def _magic_numbers(file_ctx, content, issues):
    """SOL-LOW-005: Magic numbers (unexplained numeric literals) in business logic."""
    # Numbers that are meaningful but not obvious — not 0, 1, 2, 100, 1e18 etc.
    pattern = re.compile(r'\b(\d{4,})\b')
    obvious = {10000, 100000, 1000000, 10**18, 10**6, 86400, 3600, 365}
    found = set()
    for m in pattern.finditer(content):
        val = int(m.group(1))
        if val in obvious or val in found:
            continue
        # Skip if it's in a comment, address, or version string
        line_num = content[:m.start()].count('\n') + 1
        line_content = content.splitlines()[line_num-1] if line_num <= len(content.splitlines()) else ""
        if '//' in line_content.split(m.group(1))[0]:
            continue
        if re.search(r'0x[0-9a-fA-F]*' + m.group(1), content[max(0,m.start()-3):m.end()+1]):
            continue
        found.add(val)
        if len(found) > 2:
            break
        issues.append(Issue(
            id="SOL-LOW-005",
            title=f"Magic Number: `{val}` — Use a Named Constant",
            severity=Severity.LOW, confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=line_num,
            snippet=file_ctx.get_snippet(line_num, context=2),
            description=f"The literal `{val}` is used without explanation. Magic numbers reduce readability and make it easy to introduce bugs when the value needs to change.",
            exploit_scenario="Developer changes one occurrence of the magic number but misses another — inconsistent behavior.",
            remediation=f"```solidity\nuint256 constant MY_VALUE = {val};\n```",
            references=["Pashov audit methodology: code clarity"],
            language="solidity",
        ))


def _assembly_usage(file_ctx, content, issues):
    """SOL-INFO-001: Inline assembly detected — requires extra scrutiny."""
    if not re.search(r'\bassembly\b\s*\{', content):
        return
    m = re.search(r'\bassembly\b\s*\{', content)
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-INFO-001",
        title="Inline Assembly Detected — Manual Review Required",
        severity=Severity.INFO, confidence=Confidence.HIGH,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=4),
        description=(
            "Inline assembly bypasses Solidity's type safety and security checks. "
            "While often necessary for gas optimization, it must be carefully reviewed "
            "for memory safety, return value handling, and unintended side effects."
        ),
        exploit_scenario="Assembly code incorrectly handles memory pointers, overwriting adjacent storage slots or leaking sensitive data.",
        remediation="Ensure all assembly blocks are thoroughly commented and audited. Prefer Solidity equivalents where gas savings are not critical.",
        references=["Trail of Bits: assembly-review", "https://docs.soliditylang.org/en/latest/assembly.html"],
        language="solidity",
    ))


def _upgradeable_detected(file_ctx, content, issues):
    """SOL-INFO-002: Upgradeable pattern detected — storage layout must be managed."""
    if not re.search(r'(UUPSUpgradeable|TransparentUpgradeable|Initializable|__gap)', content):
        return
    m = re.search(r'(UUPSUpgradeable|TransparentUpgradeable|Initializable)', content)
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-INFO-002",
        title="Upgradeable Contract Detected — Storage Layout Discipline Required",
        severity=Severity.INFO, confidence=Confidence.HIGH,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=2),
        description=(
            "This contract uses an upgradeable proxy pattern. Key risks:\n"
            "1. Adding new state variables must only append to the layout (never insert/reorder).\n"
            "2. `__gap` arrays must be sized to reserve future slots.\n"
            "3. Constructor logic must use `initialize()` pattern.\n"
            "4. `_authorizeUpgrade()` must have strict access control."
        ),
        exploit_scenario="New version adds a state variable at the wrong position — collides with existing data, corrupting balances or ownership.",
        remediation="Use OpenZeppelin Upgrades plugin storage gap checker. Always run `npx hardhat check` before upgrading.",
        references=["https://docs.openzeppelin.com/upgrades-plugins/1.x/", "EIP-1967"],
        language="solidity",
    ))


def _external_dependency(file_ctx, content, issues):
    """SOL-INFO-003: External protocol calls detected — integration risk."""
    ext_protocols = re.compile(
        r'(IUniswap|ICompound|IAave|ICurve|IBalancer|IChainlink|AggregatorV3'
        r'|ILido|IMaker|IConvex|IPancake|I\w+Router)',
        re.MULTILINE
    )
    found = set()
    for m in ext_protocols.finditer(content):
        name = m.group(1)
        if name not in found:
            found.add(name)
    if found:
        line = 1
        issues.append(Issue(
            id="SOL-INFO-003",
            title=f"External Protocol Dependencies: {', '.join(sorted(found))}",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet="",
            description=(
                f"This contract integrates with external protocols: `{'`, `'.join(sorted(found))}`. "
                "Each integration adds trust assumptions and failure modes — if any external "
                "protocol is paused, hacked, or behaves unexpectedly, this contract may break."
            ),
            exploit_scenario="External protocol is paused for emergency. This contract's functions that call it revert — users cannot withdraw.",
            remediation="Add circuit breakers, fallback oracles, and emergency pause functionality for all external integrations.",
            references=["Solodit: external-dependency-risk", "Pashov: integration-risk"],
            language="solidity",
        ))


def _missing_natspec(file_ctx, content, issues):
    """SOL-LOW-006: Public/external functions missing NatSpec documentation."""
    # Only flag if NO NatSpec at all in the file
    has_natspec = bool(re.search(r'///|/\*\*', content))
    if has_natspec:
        return
    pub_fn_count = len(re.findall(r'function\s+\w+[^{]*(?:public|external)', content))
    if pub_fn_count >= 3:
        issues.append(Issue(
            id="SOL-LOW-006",
            title="Missing NatSpec Documentation on Public Functions",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=1,
            snippet="",
            description=(
                f"This file has {pub_fn_count} public/external functions but no NatSpec "
                "documentation (`///` or `/** */`). NatSpec is essential for auditors, "
                "integrators, and users to understand intended behavior."
            ),
            exploit_scenario="Auditors miss intended behavior due to lack of documentation — vulnerabilities go undetected.",
            remediation=(
                "Add NatSpec to all public functions:\n"
                "```solidity\n"
                "/// @notice Withdraws user's full balance\n"
                "/// @param amount The amount to withdraw in wei\n"
                "/// @return success Whether the transfer succeeded\n"
                "function withdraw(uint256 amount) external returns (bool success) { ... }\n"
                "```"
            ),
            references=["Pashov audit methodology", "https://docs.soliditylang.org/en/latest/natspec-format.html"],
            language="solidity",
        ))


def _deprecated_functions(file_ctx, content, issues):
    """SOL-LOW-007: Deprecated Solidity functions/patterns."""
    deprecated = {
        r'\bsuicide\s*\(': ('suicide()', 'selfdestruct()', 'SWC-106'),
        r'\bsha3\s*\(': ('sha3()', 'keccak256()', 'SWC'),
        r'\bthrow\b': ('throw', 'revert()', 'SWC-110'),
        r'block\.blockhash\s*\(': ('block.blockhash()', 'blockhash()', 'Solidity docs'),
        r'callcode\s*\(': ('callcode()', 'delegatecall()', 'SWC-111'),
    }
    for pattern, (deprecated_name, replacement, ref) in deprecated.items():
        m = re.search(pattern, content)
        if m:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-LOW-007",
                title=f"Deprecated Function: `{deprecated_name}` → Use `{replacement}`",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=2),
                description=f"`{deprecated_name}` is deprecated and will be removed in future Solidity versions. Use `{replacement}` instead.",
                exploit_scenario="Deprecated function removed in future compiler — contract fails to compile or behaves unexpectedly.",
                remediation=f"Replace `{deprecated_name}` with `{replacement}`.",
                references=[ref, "https://docs.soliditylang.org/en/latest/080-breaking-changes.html"],
                language="solidity",
            ))
